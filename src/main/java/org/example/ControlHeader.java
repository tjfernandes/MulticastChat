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
        DataOutputStream out = new DataOutputStream(bos);

        out.writeInt(version);
        out.writeLong(magic);
        out.writeUTF(hashedSenderName);

        out.close();
        return bos.toByteArray();
    }

    public static ControlHeader deserialize(byte[] controlHeaderBytes) throws IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(controlHeaderBytes);
        DataInputStream in = new DataInputStream(bis);

        int version = in.readInt();
        long magic = in.readLong();
        String hashedSenderName = in.readUTF();

        return new ControlHeader(version, magic, hashedSenderName);
    }
}