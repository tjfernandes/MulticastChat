package org.example;

import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class CryptoStuff {

    private static CryptoStuff instance;

    private final PrivateKey privateKey;


    private CryptoStuff() {
        privateKey = getPrivateKey(SecureMulticastChat.username+"private", ".pem");
    }


    public static CryptoStuff getInstance() {
        if (instance == null) {
            instance = new CryptoStuff();
        }
        return instance;
    }

    public PrivateKey getPrivateKey(String prefix, String suffix)  {
        KeyFactory factory = null;
        try {
            if (SecurityProperties.SIGNATURE.equals("SHA256withRSA/PSS")) {
                factory = KeyFactory.getInstance("RSA", "BC");
            } else {
                factory = KeyFactory.getInstance("ECDSA", "BC");
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
        String path = "/keys/"+prefix+suffix;
        InputStream inputStream = getClass().getResourceAsStream(path);

        if (inputStream != null) {
            try {
                File tempFile = File.createTempFile(prefix, suffix);
                try (FileOutputStream outputStream = new FileOutputStream(tempFile)) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = inputStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                    }
                }

                try (FileReader keyReader = new FileReader(tempFile);
                     BufferedReader bufferedReader = new BufferedReader(keyReader)) {

                    String line;
                    StringBuilder privateKeyContent = new StringBuilder();
                    boolean inPrivateKeySection = false;

                    while ((line = bufferedReader.readLine()) != null) {
                        if (line.startsWith("-----BEGIN PRIVATE KEY-----")) {
                            inPrivateKeySection = true;
                        } else if (line.startsWith("-----END PRIVATE KEY-----")) {
                            inPrivateKeySection = false;
                            break; // Private key section has ended
                        } else if (inPrivateKeySection) {
                            privateKeyContent.append(line);
                        }
                    }
                    String privateKey = privateKeyContent.toString();
                    byte[] content = Base64.getDecoder().decode(privateKey);
                    PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
                    return factory.generatePrivate(privKeySpec);
                }

            } catch (IOException | InvalidKeySpecException e) {
                e.printStackTrace();
            } finally {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } else {
            System.err.println("Resource not found.");
        }

        return null;
    }

    public PublicKey getSenderPublicKey(String username) {
        try (InputStream inputStream = getClass().getResourceAsStream("/publickeys.conf");
             Scanner scanner = new Scanner(inputStream)) {

            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                String[] parts = line.split(":");

                if (parts.length >= 3 && parts[0].equals(username)) {
                    String publicKeyHex = parts[2];
                    String publicKey = Utils.hexToString(publicKeyHex);
                    byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
                    X509EncodedKeySpec keySpec =  new X509EncodedKeySpec(publicKeyBytes);
                    KeyFactory keyFactory;
                    if (SecurityProperties.SIGNATURE.equals("SHA256withRSA/PSS")) {
                        keyFactory = KeyFactory.getInstance("RSA", "BC");
                    } else {
                        keyFactory = KeyFactory.getInstance("ECDSA", "BC");
                        //not working
                    }
                    return keyFactory.generatePublic(keySpec);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] encrypt(Key key, byte[] inputBytes) throws CryptoException, InvalidAlgorithmParameterException {
        return doCrypto(Cipher.ENCRYPT_MODE, key, inputBytes);
    }

    public byte[] decrypt(Key key, byte[] inputBytes) throws CryptoException, InvalidAlgorithmParameterException {
        return doCrypto(Cipher.DECRYPT_MODE, key, inputBytes);
    }

    private byte[] doCrypto(int cipherMode, Key key, byte[] inputBytes)
            throws CryptoException, InvalidAlgorithmParameterException {
        try {
            Cipher cipher = Cipher.getInstance(SecurityProperties.CONFIDENTIALITY, "BC");

            switch (SecurityProperties.CONFIDENTIALITY) {
                case "AES/GCM/NoPadding":
                    GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, SecurityProperties.IV);
                    cipher.init(cipherMode, key, gcmParameterSpec);
                    break;
                case "AES/CTR/NoPadding", "AES/CBC/PKCS5Padding", "Blowfish/CBC/PKCS5Padding", "RC6/CCM/NoPadding":
                    IvParameterSpec ivSpec = new IvParameterSpec(SecurityProperties.IV);
                    cipher.init(cipherMode, key, ivSpec);
                    break;
                case "RC4", "CHACHA-20":
                    cipher.init(cipherMode, key);
                    break;
            }


            return cipher.doFinal(inputBytes);

        } catch ( BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ex) {
            throw new CryptoException("Error encrypting/decrypting data: \n" + ex.getMessage());
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }


    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
