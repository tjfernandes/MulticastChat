package org.example;

import java.io.*;

public class ControlHeader implements Serializable {
    int version;
    long magic;
    String hashedSenderName;

    public ControlHeader(int version, long magic, String hashedSenderName) {
        this.version = version;
        this.magic = magic;
        this.hashedSenderName = hashedSenderName;
    }

    public int getVersion() {
        return version;
    }

    public long getMagic() {
        return magic;
    }

    public String getHashedUsername() {
        return hashedSenderName;
    }

    public byte[] serialize() throws IOException{
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(bos);
        out.writeObject(this);
        out.close();
        return bos.toByteArray();
    }

    public static ControlHeader deserialize(byte[] controlHeaderBytes) {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(controlHeaderBytes);
        ObjectInputStream objectInputStream = null;
        ControlHeader controlHeader = null;
        try {
            objectInputStream = new ObjectInputStream(byteArrayInputStream);
            controlHeader = (ControlHeader) objectInputStream.readObject();
        } catch(IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return controlHeader;
    }
}