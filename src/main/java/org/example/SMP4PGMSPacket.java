package org.example;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

public class SMP4PGMSPacket implements Serializable {
    private final ControlHeader controlHeader;
    private final byte[] digitalSignature;
    private final byte[] encryptedPayload;
    private final byte[] hMacProof;

    public SMP4PGMSPacket(ControlHeader controlHeader, byte[] digitalSignature, byte[] encryptedPayload, byte[] hMacProof)
        throws NoSuchAlgorithmException, InvalidKeyException, IOException {

        this.controlHeader = controlHeader;
        this.digitalSignature = digitalSignature;
        this.encryptedPayload = encryptedPayload;
        this.hMacProof = hMacProof;

    }

    public ControlHeader getControlHeader() {
        return controlHeader;
    }

    public byte[] getDigitalSignature() {
        return digitalSignature;
    }

    public byte[] getEncryptedPayload() {
        return encryptedPayload;
    }

    public byte[] getHMac() {
        return hMacProof;
    }


    public void serialize(DataOutputStream out) throws IOException {
        ObjectOutputStream objectOut = new ObjectOutputStream(out);
        objectOut.writeObject(this);
        objectOut.close();
    }

    public static SMP4PGMSPacket deserialize(byte[] packetBytes) throws IOException, ClassNotFoundException {
        ByteArrayInputStream byteIn = new ByteArrayInputStream(packetBytes);
        ObjectInputStream objectIn = new ObjectInputStream(byteIn);
        return (SMP4PGMSPacket) objectIn.readObject();
    }
    
}
