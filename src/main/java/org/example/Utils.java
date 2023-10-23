package org.example;

import java.io.*;
import java.net.DatagramPacket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


/**
 * Utilities 
 */
public class Utils
    extends UtilsBase
{
    /**
     * Criacao de uma chave AES
     * 
     * @param bitLength
     * @param random
     * @return Chave AES
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static SecretKey createKeyForAES(
        int          bitLength,
        SecureRandom random)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        
        generator.init(256, random);
        
        return generator.generateKey();
    }
    
    /**
     * Criar um IV para usar em AES e modo CTR
     * <p>
     * IV composto por 4 bytes (numero de emensagem)
     * 4 bytes de random e um contador de 8 bytes.
     * 
     * @param messageNumber - Numero da mensagem
     * @param random - source ou seed para random
     * @return Vector IvParameterSpec inicializado
     */
    public static IvParameterSpec createCtrIvForAES(
        int             messageNumber,
        SecureRandom    random)
    {
        byte[]          ivBytes = new byte[16];
        
        // initially randomize
        
        random.nextBytes(ivBytes);
        
        // set the message number bytes
        
        ivBytes[0] = (byte)(messageNumber >> 24);
        ivBytes[1] = (byte)(messageNumber >> 16);
        ivBytes[2] = (byte)(messageNumber >> 8);
        ivBytes[3] = (byte)(messageNumber >> 0);
        
        // set the counter bytes to 1
        
        for (int i = 0; i != 7; i++)
        {
            ivBytes[8 + i] = 0;
        }
        
        ivBytes[15] = 1;
        
        return new IvParameterSpec(ivBytes);
    }
    
    /**
     * Converte um byte array de 8 bits numa string
     * 
     * @param bytes array contendo os caracteres
     * @param length N. de bytes a processar
     * @return String que representa os bytes
     */
    public static String toString(
        byte[] bytes,
        int    length)
    {
        char[]	chars = new char[length];
        
        for (int i = 0; i != chars.length; i++)
        {
            chars[i] = (char)(bytes[i] & 0xff);
        }
        
        return new String(chars);
    }
    
    /**
     * Convete um array de caracteres de 8 bits numa string
     * 
     * @param bytes - Array que contem os caracteres
     * @return String com a representacao dos bytes
     */
    public static String toString(
        byte[]	bytes)
    {
        return toString(bytes, bytes.length);
    }
    
    /**
     * Converte a string passada num array de bytes
     * a partir dos 8 bits de cada caracter contido no array
     * 
     * @param string - String a converter
     * @return - retorna representacao em array de bytes 
     */
    public static byte[] toByteArray(
        String string)
    {
        byte[]	bytes = new byte[string.length()];
        char[]  chars = string.toCharArray();
        
        for (int i = 0; i != chars.length; i++)
        {
            bytes[i] = (byte)chars[i];
        }
        
        return bytes;
    }

    public static byte[] hexToByteArray(String hex) {
        int length = hex.length();
        byte[] data = new byte[length / 2];

        for (int i = 0; i < length; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }

        return data;
    }


    /**
     * Hashes a string and returns it in a hexadecimal string
     * @param text - text to hash
     * @param algorithm - algorithm for digest
     * @return hashed hexadecimal string
     * @throws NoSuchAlgorithmException
     */
    public static String hashString(String text, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] encodedHash = digest.digest(toByteArray(text));

        return toHex(encodedHash);
    }

    public static Long generateNonce() {
        SecureRandom secureRandom = new SecureRandom();
        return secureRandom.nextLong();
    }

    public static void writePacket(DataOutputStream dataStream, SMP4PGMSPacket packet) throws IOException {
        packet.serialize(dataStream);
    }

    public static byte[] generateHmac(Key hMacKey, ControlHeader controlHeader, byte[] encryptedPayloadBytes, String macAlgorithm) throws NoSuchAlgorithmException, InvalidKeyException, IOException, NoSuchProviderException {

        Mac hMac = Mac.getInstance(macAlgorithm, "BC");
        hMac.init(hMacKey);

        byte[] controlHeaderBytes = controlHeader.serialize();

        byte[] dataToHash = new byte[controlHeaderBytes.length + encryptedPayloadBytes.length];
        System.arraycopy(controlHeaderBytes, 0, dataToHash, 0, controlHeaderBytes.length);
        System.arraycopy(encryptedPayloadBytes, 0, dataToHash, controlHeaderBytes.length, encryptedPayloadBytes.length);


        return hMac.doFinal(dataToHash);
    }

    public static byte[] getEncryptPayload(Key key, Payload payload, String algorithm) throws IOException, CryptoException, InvalidAlgorithmParameterException {
        byte[] serializedPayload = payload.serialize();
        return CryptoStuff.getInstance().encrypt(key, serializedPayload);
    }

    public static Payload getDecryptedPayload(Key confidentialityKey, byte[] encryptedPayload, String algorithm) throws CryptoException, ClassNotFoundException, IOException, InvalidAlgorithmParameterException {
        byte[] decryptedPayload = CryptoStuff.getInstance().decrypt(confidentialityKey, encryptedPayload);
        return Payload.deserialize(decryptedPayload);
    }

    public static Payload processPacketAndGetPayload(DatagramPacket packet, Key macKey, String macAlgorithm, Key key, Map<String, Set<Long>> nonceCache, String algorithm) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, CryptoException, NoSuchProviderException {
        DataInputStream istream = new DataInputStream(new ByteArrayInputStream(packet.getData(), packet.getOffset(), packet.getLength()));

        SMP4PGMSPacket smp4pgmsPacket = SMP4PGMSPacket.deserialize(istream.readAllBytes());
        ControlHeader controlHeader = smp4pgmsPacket.getControlHeader();
        byte[] encryptedPayload = smp4pgmsPacket.getEncryptedPayload();

        byte[] hMacReceived = smp4pgmsPacket.getHMac();
        byte[] hMacValue = generateHmac(macKey, controlHeader, encryptedPayload, macAlgorithm);

        if (!MessageDigest.isEqual(hMacReceived, hMacValue)) {
            System.out.println("WARNING: User is not verified!!! This message is not theirs");
            return null;
        }

        Payload decryptedPayload = getDecryptedPayload(key, encryptedPayload, algorithm);
        Long receivedNonce = decryptedPayload.getNonce();

        String senderName = decryptedPayload.getSenderName();

        Set<Long> senderNonces = nonceCache.computeIfAbsent(senderName, k -> new ConcurrentSkipListSet<>());

        if (senderNonces.contains(receivedNonce) ) {
            System.out.println("WARNING: This message is being replayed!");
            return null;
        } else {
            senderNonces.add(receivedNonce);
        }

        // Only accepts CHAT-MAGIC-NUMBER of the Chat
        if (controlHeader.getMagic() != SecureMulticastChat.CHAT_MAGIC_NUMBER) {
            return null;
        }

        return decryptedPayload;
    }


}
