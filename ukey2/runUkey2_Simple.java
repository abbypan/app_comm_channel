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


public class runUkey2 {
    private static final int MAX_AUTH_STRING_LENGTH = 32;

    public static String runUkey2(String c2sFileName, String s2cFileName) throws Exception {
        try {
            long startTime = System.nanoTime();
            Ukey2Handshake client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512);
            Ukey2Handshake server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512);

            // Message 1 (Client Init)
            byte[] handshakeMessage1;
            handshakeMessage1 = client.getNextHandshakeMessage();
            server.parseHandshakeMessage(handshakeMessage1);
            //System.out.println("handshakeMessage1: " + handshakeMessage1.length + "\n" + formatFingerprint.formatHex(handshakeMessage1));        

            // Message 2 (Server Init)
            byte[] handshakeMessage2;
            handshakeMessage2 = server.getNextHandshakeMessage();
            client.parseHandshakeMessage(handshakeMessage2);
            //System.out.println("handshakeMessage2: " + handshakeMessage2.length + "\n" + formatFingerprint.formatHex(handshakeMessage2));        

            // Message 3 (Client Finish)
            byte[] handshakeMessage3;
            handshakeMessage3 = client.getNextHandshakeMessage();
            server.parseHandshakeMessage(handshakeMessage3);
            //System.out.println("handshakeMessage3: " + handshakeMessage3.length + "\n" + formatFingerprint.formatHex(handshakeMessage3));        

            // Get the auth string
            byte[] clientAuthString = client.getVerificationString(MAX_AUTH_STRING_LENGTH);
            byte[] serverAuthString = server.getVerificationString(MAX_AUTH_STRING_LENGTH);

            //System.out.println("clientAuthString: " + clientAuthString.length + "\n" + formatFingerprint.formatHex(clientAuthString));        
            //System.out.println("serverAuthString: " + serverAuthString.length + "\n" + formatFingerprint.formatHex(serverAuthString));        

            // Verify the auth string
            client.verifyHandshake();
            server.verifyHandshake();

            // Make a context
            D2DConnectionContext clientContext = client.toConnectionContext();
            D2DConnectionContext serverContext = server.toConnectionContext();

            long handshakeTime = System.nanoTime();

            String PING =  new String(Files.readAllBytes(Paths.get(c2sFileName)));
            byte[] pingMessage = clientContext.encodeMessageToPeer(PING);
            //System.out.println("pingMessage: " + pingMessage.length + "\n" + formatFingerprint.formatHex(pingMessage));        
            String pingMessageDecode = serverContext.decodeMessageFromPeerAsString(pingMessage);
            //System.out.println("pingMessageDecode: " + pingMessageDecode.length() + "\n" + pingMessageDecode);        

            String PONG =   new String(Files.readAllBytes(Paths.get(s2cFileName)));
            byte[] pongMessage = serverContext.encodeMessageToPeer(PONG);
            //System.out.println("pongMessage: " + pongMessage.length + "\n" + formatFingerprint.formatHex(pongMessage));        
            String pongMessageDecode = clientContext.decodeMessageFromPeerAsString(pongMessage);
            //System.out.println("pongMessageDecode: " + pongMessageDecode.length() + "\n" + pongMessageDecode);        

            long commTime = System.nanoTime();

            long elapsedHandshake = handshakeTime - startTime;
            long elapsedComm = commTime - handshakeTime;

            String result = "ukey2," + c2sFileName + "," + s2cFileName + "," + 
                handshakeMessage1.length + "," + handshakeMessage2.length + "," + handshakeMessage3.length + "," + 
                pingMessage.length + "," + pingMessageDecode.length() + "," + 
                pongMessage.length + "," + pongMessageDecode.length()  + "," + 
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

        String res = runUkey2(c2sFileName, s2cFileName);
        System.out.println(res);
    }
}
