# 原理
Java对象在LDAP目录中有多种存储形式：
* Java序列化
* JNDI Reference
* Marshalled对象

LDAP可以为存储的Java对象指定多种属性：
* javaCodeBase
* objectClass
* javaFactory
* javaSerializedData
* .....

这里讨论的就是javaSerializedData，这个属性可以写入序列化数据，在lookup过程中会对其进行反序列化，因此我们可以直接用ysoserial生成Gadget的序列化数据然后写入javaSerializedData，这样就可以在目标lookup时反序列化利用，只要目标存在响应依赖的话。

具体原理在com.sun.jndi.ldap.decodeObject的decodeObject方法中，他会检查是否有javaSerializedData，如果有的话，会调用deserializeObject对其进行反序列化
```java
static Object decodeObject(Attributes var0) throws NamingException {
    String[] var2 = getCodebases(var0.get(JAVA_ATTRIBUTES[4]));

    try {
        Attribute var1;
        if ((var1 = var0.get(JAVA_ATTRIBUTES[1])) != null) {  // 检查是否有javaSerializedData
            if (!helper.isSerialDataAllowed()) {
                throw new NamingException("Object deserialization is not allowed");
            } else {
                ClassLoader var3 = helper.getURLClassLoader(var2);
                return deserializeObject((byte[])((byte[])var1.get()), var3);  // 这里跟进
            }
            ...
        }
        ...
    }
    ...
}
```
在这里，会把byte数组转ByteArrayInputStream，再转ObjectInputStream，最后readObject：
```java
private static Object deserializeObject(byte[] var0, ClassLoader var1) throws NamingException {
    try {
        ByteArrayInputStream var2 = new ByteArrayInputStream(var0);

        try {
            Object var20 = var1 == null ? new ObjectInputStream(var2) : new Obj.LoaderInputStream(var2, var1);
            Throwable var21 = null;

            Object var5;
            try {
                var5 = ((ObjectInputStream)var20).readObject();
            }
            ...
        }
        ...
    }
    ...
}
```

# 复现

先在IDEA中，把`lib/unboundid-ldapsdk-3.1.1.jar`添加到SDK。  

然后启动`LDAPServer#main`，接着再运行`LookupCase#main`即可。

# 参考文献

[如何绕过高版本JDK的限制进行JNDI注入利用 – KINGX](https://kingx.me/Restrictions-and-Bypass-of-JNDI-Manipulations-RCE.html#/)

[kxcode/JNDI-Exploit-Bypass-Demo: Demo code for post <Restrictions of JNDI Manipulation RCE & Bypass>](https://github.com/kxcode/JNDI-Exploit-Bypass-Demo#/)