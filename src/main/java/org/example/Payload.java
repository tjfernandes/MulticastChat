package org.example;

import java.io.*;

public class Payload implements Serializable {
    private final String senderName;
    private final int type;
    private final Long nonce;
    private final String message;

    public Payload(String senderName, int type, Long nonce, String message) {
        this.senderName = senderName;
        this.type = type;
        this.nonce = nonce;
        this.message = message;
    }

    public Payload(String senderName, int type, Long nonce) {
        this.senderName = senderName;
        this.type = type;
        this.nonce = nonce;
        this.message = "";
    }

    public Payload(byte[] bytes) throws IOException{
        ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
        ObjectInput in = new ObjectInputStream(bis);

        this.senderName = in.readUTF();
        this.type = in.readInt();
        this.nonce = in.readLong();
        this.message = in.readUTF();
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

    public static Payload deserialize(byte[] payloadBytes) throws IOException, ClassNotFoundException {
        ByteArrayInputStream bis = new ByteArrayInputStream(payloadBytes);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return (Payload) ois.readObject();
    }



}