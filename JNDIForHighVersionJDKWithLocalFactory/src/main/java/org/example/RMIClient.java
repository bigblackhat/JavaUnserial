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
