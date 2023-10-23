package org.example;

import java.security.*;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class CryptoStuff {

    private static CryptoStuff instance;

    private static final byte[] ivBytes  = new byte[]
     {
	      0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 ,
        0x0f, 0x0d, 0x0e, 0x0c
     };



    private CryptoStuff() {
    }


    public static CryptoStuff getInstance() {
        if (instance == null) {
            instance = new CryptoStuff();
        }
        return instance;
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
                    Cipher.getInstance(SecurityProperties.CONFIDENTIALITY, "BC");
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

    private byte[] generateRandomIV() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[12]; // 96 bits IV for AES-GCM
        secureRandom.nextBytes(iv);
        return iv;
    }
}
