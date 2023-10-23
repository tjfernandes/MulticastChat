package org.example;// MulticastChat.java
// Represents the Multicast Chat/Messaging Protocol
// As you can see, the used Multicast Communication Channel
// is not secure .... Messages flow as plaintext messages
// You can see that if an adversary inspects traffic w/ a tool such as Wireshark,
// she/he know everything the users are saying in the Chat ...
// Also ... she/he can also operate as a Man In The Middle .... and it is easy
// for her/him to cheat/fool the users

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SecureMulticastChat extends Thread {

    // Definition of opcode for JOIN type
    public static final int JOIN = 1;

    // Definition of opcode for LEAVE type
    public static final int LEAVE = 2;

    // Definition of opcode for a regular message type (sent/received)
    public static final int MESSAGE = 3;

    // Definition of a MAGIC NUMBER (as a global identifier) for the CHAT
    public static final long CHAT_MAGIC_NUMBER = 4969756929653643804L;

    // Timeout for sockets
    public static final int DEFAULT_SOCKET_TIMEOUT_MILLIS = 5000;

    // Version of SecureMulticastChat
    private static final int VERSION = 1;

    // Security properties
    public static SecurityProperties properties;

    // Stored nonces
    Map<String, Set<Long>> nonceCache = new ConcurrentHashMap<>();

    // Multicast socket used to send and receive multicast protocol PDUs
    protected MulticastSocket msocket;

    // Username / User-Nick-Name in Chat
    protected String username;

    // Grupo IP Multicast used
    protected InetAddress group;

    // Listener for Multicast events that must be processed
    protected MulticastChatEventListener listener;

    // Control - execution thread

    protected boolean isActive;

    // Multicast Chat-Messaging
    public SecureMulticastChat(String username, InetAddress group, int port,
                               int ttl, MulticastChatEventListener listener)
            throws Exception {

        this.username = username;
        this.group = group;
        this.listener = listener;
        isActive = true;

        properties = new SecurityProperties();

        // create & configure multicast socket

        msocket = new MulticastSocket(port);
        msocket.setSoTimeout(DEFAULT_SOCKET_TIMEOUT_MILLIS);
        msocket.setTimeToLive(ttl);
        msocket.joinGroup(group);

        // start receive thread and send multicast join message
        start();
        sendJoin();
    }

    /**
     * Sent notification when user wants to leave the Chat-messaging room
     *
     * @throws CryptoException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     */

    public void terminate() throws IOException, InvalidKeyException, NoSuchAlgorithmException, CryptoException, InvalidAlgorithmParameterException, NoSuchProviderException {
        isActive = false;
        sendLeave();
    }

    // to process error message
    protected void error(String message) {
        System.err.println(new java.util.Date() + ": MulticastChat: "
                + message);
    }

    // Send a JOIN message
    //
    protected void sendJoin() throws IOException, InvalidKeyException, NoSuchAlgorithmException, CryptoException, InvalidAlgorithmParameterException, NoSuchProviderException {
        processSendPacket(JOIN, "");
    }

    // Process recived JOIN message
    //
    protected void processJoin(Payload payload, InetAddress address, int port) throws IOException {
        String name = payload.getSenderName();

        try {
            listener.chatParticipantJoined(name, address, port);
        } catch (Throwable e) {
        }
    }

    // Send LEAVE
    protected void sendLeave() throws IOException, CryptoException, InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        processSendPacket(LEAVE, "");
    }

    // Processes a multicast chat LEAVE and notifies listeners

    protected void processLeave(Payload payload, InetAddress address, int port) throws IOException {
        String username = payload.getSenderName();

        try {
            listener.chatParticipantLeft(username, address, port);
        } catch (Throwable e) {
        }
    }

    // Send message to the chat-messaging room
    //
    public void sendMessage(String message) throws IOException, CryptoException, InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        processSendPacket(MESSAGE, message);
    }

    // Process a received message //
    //
    protected void processMessage(Payload payload, InetAddress address, int port) throws IOException {
        String username = payload.getSenderName();
        String message = payload.getMessage();

        try {
            listener.chatMessageReceived(username, address, port, message);
        } catch (Throwable e) {
        }
    }

    private void processSendPacket(int type, String message) throws InvalidAlgorithmParameterException, IOException, CryptoException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        String hashedUsername = Utils.hashString(username, SecurityProperties.HASHFORNICKNAMES);
        ControlHeader controlHeader = new ControlHeader(SecureMulticastChat.VERSION, SecureMulticastChat.CHAT_MAGIC_NUMBER, hashedUsername);

        Long nonce = Utils.generateNonce();

        Payload payload = new Payload(username, type, nonce, message);

        byte[] encryptedPayload = Utils.getEncryptPayload(SecurityProperties.CONFIDENTIALITY_KEY, payload, SecurityProperties.CONFIDENTIALITY);

        byte[] hMacProof = Utils.generateHmac(SecurityProperties.MACKEY, controlHeader, encryptedPayload, SecurityProperties.MACALGORITHM);

        SMP4PGMSPacket smp4pgmsPacket = new SMP4PGMSPacket(controlHeader, encryptedPayload, hMacProof);

        Utils.writePacket(dataStream, smp4pgmsPacket);

        dataStream.close();

        byte[] data = byteStream.toByteArray();
        DatagramPacket packet = new DatagramPacket(data, data.length, group,
                msocket.getLocalPort());
        msocket.send(packet);
    }

    // Loop:
    // reception and demux received datagrams to process,
    // according with message types and opcodes
    //
    public void run() {
        byte[] buffer = new byte[65508];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

        while (isActive) {
            try {
                packet.setLength(buffer.length);
                msocket.receive(packet);
                Payload decryptedPayload = Utils.processPacketAndGetPayload(packet, SecurityProperties.MACKEY, SecurityProperties.MACALGORITHM,
                        SecurityProperties.CONFIDENTIALITY_KEY, nonceCache, SecurityProperties.CONFIDENTIALITY);

                if (decryptedPayload == null) {
                    continue;
                }

                int opCode = decryptedPayload.getType();
                switch (opCode) {
                    case JOIN:
                        processJoin(decryptedPayload, packet.getAddress(), packet.getPort());
                        break;
                    case LEAVE:
                        processLeave(decryptedPayload, packet.getAddress(), packet.getPort());
                        break;
                    case MESSAGE:
                        processMessage(decryptedPayload, packet.getAddress(), packet.getPort());
                        break;
                    default:
                        error("rror; Unknown type " + opCode + " sent from  "
                                + packet.getAddress() + ":" + packet.getPort());
                }

            } catch (InterruptedIOException e) {

                /**
                 * Handler for Interruptions ...
                 * WILL DO NOTHING ,,,
                 * Used for debugging / control if wanted ... to notify the loop interruption
                 */

            } catch (Throwable e) {
                error("Processing error: " + e.getClass().getName() + ": "
                        + e.getMessage());
            }
        }

        try {
            msocket.close();
        } catch (Throwable e) {
        }
    }
}
