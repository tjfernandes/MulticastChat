package org.example;

import java.io.*;

public class SignatureData implements Serializable {

    private final ControlHeader controlHeader;

    private final String senderName;

    private final int type;

    private final Long nonce;

    private final String message;

    public SignatureData(ControlHeader controlHeader, String senderName, int type, Long nonce, String message) {
        this.controlHeader = controlHeader;
        this.senderName = senderName;
        this.type = type;
        this.nonce = nonce;
        this.message = message;


    }

    public ControlHeader getControlHeader() {
        return controlHeader;
    }

    public String getSenderName() {
        return senderName;
    }

    public int getType() {
        return type;
    }

    public Long getNonce() {
        return nonce;
    }

    public String getMessage() {
        return message;
    }

    public byte[] serialize() throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(this);
        oos.close();
        return bos.toByteArray();
    }

}
