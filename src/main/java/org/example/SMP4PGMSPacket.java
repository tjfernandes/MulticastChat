package org.example;

import javax.xml.crypto.Data;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SMP4PGMSPacket implements Serializable {
    private final ControlHeader controlHeader;
    private final byte[] encryptedPayload;
    private final byte[] hMacProof;

    public SMP4PGMSPacket(ControlHeader controlHeader, byte[] encryptedPayload, byte[] hMacProof)
        throws NoSuchAlgorithmException, InvalidKeyException, IOException {

        this.controlHeader = controlHeader;
        this.encryptedPayload = encryptedPayload;
        this.hMacProof = hMacProof;

    }

    public ControlHeader getControlHeader() {
        return controlHeader;
    }

    public byte[] getEncryptedPayload() {
        return encryptedPayload;
    }

    public byte[] getHMac() {
        return hMacProof;
    }


    public void serialize(DataOutputStream out) throws IOException{

        // Control header serialization
        byte[] serializedControlHeader = controlHeader.serialize();
        out.writeInt(serializedControlHeader.length);
        out.write(serializedControlHeader);

        // Encrypted Payload serialization
        out.writeInt(encryptedPayload.length);
        out.write(encryptedPayload);

        // HMAC Proof serialization
        out.writeInt(hMacProof.length);
        out.write(hMacProof);
    }

    public static SMP4PGMSPacket deserialize(byte[] packetdBytes) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        ByteArrayInputStream bis = new ByteArrayInputStream(packetdBytes);
        DataInputStream in = new DataInputStream(bis);

        // Control Header deserialization
        int headerLength = in.readInt();
        byte[] serializedControlHeader = in.readNBytes(headerLength);
        ControlHeader controlHeader = ControlHeader.deserialize(serializedControlHeader);

        // Payload
        int encryptedPayloadLength = in.readInt();
        byte[] encryptedPayload = in.readNBytes(encryptedPayloadLength);

        // HMAC Proof
        int hMacProofLength = in.readInt();
        byte[] hMacProof = in.readNBytes(hMacProofLength);

        return new SMP4PGMSPacket(controlHeader, encryptedPayload, hMacProof);
    }
    
}
