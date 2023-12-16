import com.google.security.cryptauth.lib.securegcm.*;
import com.google.security.cryptauth.lib.securegcm.Ukey2Handshake.AlertException;
import com.google.security.cryptauth.lib.securegcm.Ukey2Handshake.HandshakeCipher;
import com.google.security.cryptauth.lib.securegcm.Ukey2Handshake.State;
import com.google.security.cryptauth.lib.securegcm.UkeyProto.Ukey2ClientFinished;
import com.google.security.cryptauth.lib.securegcm.UkeyProto.Ukey2ClientInit;
import com.google.security.cryptauth.lib.securegcm.UkeyProto.Ukey2ClientInit.CipherCommitment;
import com.google.security.cryptauth.lib.securegcm.UkeyProto.Ukey2Message;
import com.google.security.cryptauth.lib.securegcm.UkeyProto.Ukey2ServerInit;

import java.io.*;
import java.util.HexFormat;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.http.util.ByteArrayBuffer;

import java.net.Socket;
import java.net.ServerSocket;
import javax.net.ServerSocketFactory;


public class runUkey2 {
    private static final int MAX_AUTH_STRING_LENGTH = 32;

    public static byte[] readLargeInputStream(InputStream is) throws Exception {
        ByteArrayBuffer mbuf = new ByteArrayBuffer(0) ; 

        long len = 0L;
        byte[] data = new byte[1200000];
        while (true) {
            int readN = is.read(data);
            if (-1 == readN) {
                break;
            }
            //System.out.println("read from buffer " + readN);
            len += readN;
            mbuf.append(data, 0, readN);
        }
        byte[] res = mbuf.buffer();
        return res;
    }

    public static String startClient(String host, int port, String c2sFileName) throws Exception {
        try {
            long startTime = System.nanoTime();

            Socket socket = new Socket(host, port);

            InputStream is = new BufferedInputStream(socket.getInputStream());
            OutputStream os = new BufferedOutputStream(socket.getOutputStream());
            byte[] message = new byte [1200000];
            byte[] plaintext = new byte [1200000];

            Ukey2Handshake client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512);

            // Message 1 (Client Init)
            byte[] handshakeMessage1;
            handshakeMessage1 = client.getNextHandshakeMessage();
            os.write(handshakeMessage1, 0, handshakeMessage1.length);
            os.flush();
            //System.out.println("client send handshakeMessage1: " + handshakeMessage1.length + "\n" + HexFormat.of().formatHex(handshakeMessage1));        

            // Message 2 (Server Init)
            int handshake2_len = is.read(message);
            byte[] handshakeMessage2 = new byte[handshake2_len];
            System.arraycopy(message, 0, handshakeMessage2, 0, handshake2_len);
            client.parseHandshakeMessage(handshakeMessage2);
            //System.out.println("client recv handshakeMessage2: " + handshakeMessage2.length + "\n" + HexFormat.of().formatHex(handshakeMessage2));        

            // Message 3 (Client Finish)
            byte[] handshakeMessage3;
            handshakeMessage3 = client.getNextHandshakeMessage();
            os.write(handshakeMessage3, 0, handshakeMessage3.length);
            os.flush();
            //System.out.println("client send handshakeMessage3: " + handshakeMessage3.length + "\n" + HexFormat.of().formatHex(handshakeMessage3));        

            // Get the auth string
            byte[] clientAuthString = client.getVerificationString(MAX_AUTH_STRING_LENGTH);

            //System.out.println("clientAuthString: " + clientAuthString.length + "\n" + HexFormat.of().formatHex(clientAuthString));        

            // Verify the auth string
            client.verifyHandshake();

            // Make a context
            D2DConnectionContext clientContext = client.toConnectionContext();

            long handshakeTime = System.nanoTime();

            String PING =  new String(Files.readAllBytes(Paths.get(c2sFileName)));
            byte[] pingMessage = clientContext.encodeMessageToPeer(PING);
            os.write(pingMessage, 0, pingMessage.length);
            os.flush();
            socket.shutdownOutput();
            //System.out.println("client send pingMessage: " + pingMessage.length + "\n" + HexFormat.of().formatHex(pingMessage));        

            //int pong_len = is.read(message);
            //byte[] pongMessage = new byte[pong_len];
            //System.arraycopy(message, 0, pongMessage, 0, pong_len);
            byte[] pongMessage = readLargeInputStream(is);

            String pongMessageDecode = clientContext.decodeMessageFromPeerAsString(pongMessage);
            //System.out.println("client recv pongMessage: " + pongMessage.length + "\n" + HexFormat.of().formatHex(pongMessage));        
            //System.out.println("client recv pongMessageDecode: " + pongMessageDecode.length() + "\n" + pongMessageDecode);        

            long commTime = System.nanoTime();

            long elapsedHandshake = handshakeTime - startTime;
            long elapsedComm = commTime - handshakeTime;

            String result = "ukey2,client," + c2sFileName + "," + 
                handshakeMessage1.length + "," + handshakeMessage2.length + "," + handshakeMessage3.length + "," + 
                pingMessage.length + "," + PING.length() + "," + 
                pongMessage.length + "," + pongMessageDecode.length()  + "," + 
                elapsedHandshake + "," + elapsedComm
                ;

            socket.close();
            return result;
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

    }

    public static String startServer(int port, String s2cFileName) throws Exception {
            long startTime = System.nanoTime();

        ServerSocket serverS = new ServerSocket(port);
        try( Socket socket = serverS.accept()) {
            InputStream is = new BufferedInputStream(socket.getInputStream());
            OutputStream os = new BufferedOutputStream(socket.getOutputStream());
            byte[] message = new byte [1200000];
            byte[] plaintext = new byte [1200000];

            Ukey2Handshake server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512);

            // Message 1 (Client Init)
            int handshake1_len = is.read(message);
            byte[] handshakeMessage1 = new byte[handshake1_len];
            System.arraycopy(message, 0, handshakeMessage1, 0, handshake1_len);
            server.parseHandshakeMessage(handshakeMessage1);
            //System.out.println("server recv handshakeMessage1: " + handshakeMessage1.length + "\n" + HexFormat.of().formatHex(handshakeMessage1));        

            // Message 2 (Server Init)
            byte[] handshakeMessage2;
            handshakeMessage2 = server.getNextHandshakeMessage();
            os.write(handshakeMessage2, 0, handshakeMessage2.length);
            os.flush();
            //System.out.println("server send handshakeMessage2: " + handshakeMessage2.length + "\n" + HexFormat.of().formatHex(handshakeMessage2));        

            // Message 3 (Client Finish)
            int handshake3_len = is.read(message);
            byte[] handshakeMessage3 = new byte[handshake3_len];
            System.arraycopy(message, 0, handshakeMessage3, 0, handshake3_len);
            server.parseHandshakeMessage(handshakeMessage3);
            //System.out.println("server recv handshakeMessage3: " + handshakeMessage3.length + "\n" + HexFormat.of().formatHex(handshakeMessage3));        

            // Get the auth string
            byte[] serverAuthString = server.getVerificationString(MAX_AUTH_STRING_LENGTH);

            //System.out.println("serverAuthString: " + serverAuthString.length + "\n" + HexFormat.of().formatHex(serverAuthString));        

            // Verify the auth string
            server.verifyHandshake();

            // Make a context
            D2DConnectionContext serverContext = server.toConnectionContext();

            long handshakeTime = System.nanoTime();

            //int ping_len = is.read(message);
            //byte[] pingMessage = new byte[ping_len];
            //System.arraycopy(message, 0, pingMessage, 0, ping_len);

            byte[] pingMessage = readLargeInputStream(is);
            String pingMessageDecode = serverContext.decodeMessageFromPeerAsString(pingMessage);
            //System.out.println("server recv pingMessage: " + pingMessage.length + "\n" + HexFormat.of().formatHex(pingMessage));        
            //System.out.println("server recv pingMessageDecode: " + pingMessageDecode.length() + "\n" + pingMessageDecode);        

            String PONG =   new String(Files.readAllBytes(Paths.get(s2cFileName)));
            byte[] pongMessage = serverContext.encodeMessageToPeer(PONG);
            os.write(pongMessage, 0, pongMessage.length);
            os.flush();
            //System.out.println("server send pongMessage: " + pongMessage.length + "\n" + HexFormat.of().formatHex(pongMessage));        

            long commTime = System.nanoTime();

            long elapsedHandshake = handshakeTime - startTime;
            long elapsedComm = commTime - handshakeTime;

            String result = "ukey2,server," + s2cFileName + "," + 
                handshakeMessage1.length + "," + handshakeMessage2.length + "," + handshakeMessage3.length + "," + 
                pingMessage.length + "," + pingMessageDecode.length() + "," + 
                pongMessage.length + "," + PONG.length()  + "," + 
                elapsedHandshake + "," + elapsedComm
                ;

            return result;
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

    }

    public static void main(String[] args) throws Exception {
        String c2sFileName = args[0];
        String s2cFileName = args[1];

        Thread serverThread = new Thread(() -> {
            try {
                String res=startServer(33333, s2cFileName);
                System.out.println(res);
            }catch(Exception e){
                System.out.println(e);
            }
        });

        Thread clientThread = new Thread(() -> {
            try{
                String res = startClient("127.0.0.1", 33333, c2sFileName);
                System.out.println(res);
            }catch(Exception e){
                System.out.println(e);
            }
        });

        serverThread.start();;
        clientThread.start();

        serverThread.join();
        clientThread.join();
    }
}
