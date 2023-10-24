package org.example;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.util.Properties;

public class SecurityProperties {
    public static String CONFIDENTIALITY;
    public static Key CONFIDENTIALITY_KEY;
    public static byte[] IV;
    public static String HASHFORNICKNAMES;
    public static Key MACKEY;
    public static String MACALGORITHM;
    public static String SIGNATURE;

    public SecurityProperties() {
        Properties properties = new Properties();
        try {
            InputStream inputStream = getClass().getResourceAsStream("/security.conf");
            if (inputStream != null) {
                properties.load(inputStream);
                inputStream.close();
            } else {
                // Handle the case when the resource is not found
                throw new IOException("security.conf not found in resources.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        CONFIDENTIALITY = properties.getProperty("CONFIDENTIALITY");
        String algorithm = CONFIDENTIALITY.split("/")[0];
        String key = properties.getProperty("CONFIDENTIALITY-KEY");
        CONFIDENTIALITY_KEY = new SecretKeySpec(key.getBytes(), algorithm);
        String ivHex = properties.getProperty("IV");
        if (ivHex != null) {
            IV = Utils.hexToByteArray(ivHex);
        }
        HASHFORNICKNAMES = properties.getProperty("HASHFORNICKNAMES");
        MACALGORITHM = properties.getProperty("MACALGORITHM");
        MACKEY = new SecretKeySpec(properties.getProperty("MACKEY").getBytes(), MACALGORITHM);
        SIGNATURE = properties.getProperty("SIGNATURE");
    }
}
