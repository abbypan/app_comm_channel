import java.io.*;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.net.Socket;
import java.net.ServerSocket;
import javax.net.ServerSocketFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;

import com.southernstorm.noise.protocol.*;
import com.southernstorm.noise.crypto.*;
import com.southernstorm.noise.protocol.CipherState;
import com.southernstorm.noise.protocol.CipherStatePair;
import com.southernstorm.noise.protocol.HandshakeState;

import java.util.HexFormat;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.http.util.ByteArrayBuffer;

public class runNoise {
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

    private static String startClient(String host, int port, String c2sFileName) throws Exception  {

        long startTime = System.nanoTime();

        Socket socket = new Socket(host, port);

        String protocolName = "Noise_KK_P256_AESGCM_SHA256";

        byte[] init_prologue = HexFormat.of().parseHex("50726f6c6f677565313233");
        byte[] init_static = HexFormat.of().parseHex("6C01E03D2669C921D172F49E7DDB04625A7391227B99BB08979D7AA4884056AA");
        byte[] init_remote_static = HexFormat.of().parseHex("034BF8F658E2039CE631A3F28F78418A004DE061A3DD50E8896610C3A2BB4C77CC");


        HandshakeState initiator = new HandshakeState(protocolName, HandshakeState.INITIATOR);

        initiator.setPrologue(init_prologue, 0, init_prologue.length);
        initiator.getLocalKeyPair().setPrivateKey(init_static, 0);
        initiator.getRemotePublicKey().setPublicKey(init_remote_static, 0);

        initiator.start();

        int bufsize = 1200000;
        byte[] message = new byte [bufsize];
        byte[] plaintext = new byte [bufsize];

        InputStream is = new BufferedInputStream(socket.getInputStream());
        OutputStream os = new BufferedOutputStream(socket.getOutputStream());

        int handshake1_len = initiator.writeMessage(message, 0, null, 0, 0);
        os.write(message, 0, handshake1_len);
        os.flush();

        //System.out.printf("init send Handshake1: %s\n", HexFormat.of().formatHex(message,0, handshake1_len));


        int handshake2_len = is.read(message);
        int handshake2_plen = initiator.readMessage(message, 0, handshake2_len, plaintext, 0);
        //System.out.printf("init recv handshake2: %s\n", HexFormat.of().formatHex(message,0, handshake2_len));

        //System.out.printf("init handshake hash: %s\n", HexFormat.of().formatHex(initiator.getHandshakeHash(), 0, initiator.getHandshakeHash().length)); 

        CipherStatePair initPair;

        initPair = initiator.split();

        long handshakeTime = System.nanoTime();

        byte[] c2s_msg =  Files.readAllBytes(Paths.get(c2sFileName));
        byte[] c2s_cipher = new byte[c2s_msg.length + 16];
        int c2s_len = initPair.getSender().encryptWithAd(null, c2s_msg, 0, c2s_cipher, 0, c2s_msg.length);
        os.write(c2s_cipher, 0, c2s_len);
        os.flush();
        socket.shutdownOutput();
        //System.out.printf("init send cipher: c2s msg %s\n", HexFormat.of().formatHex(message, 0, c2s_len)); 
        //System.out.printf("init send plaintext: %s\n", HexFormat.of().formatHex(c2s_msg, 0, c2s_msg.length)); 

        //int s2c_len = is.read(message, 0, bufsize);
        byte[] s2c = readLargeInputStream(is);

        int s2c_plen = initPair.getReceiver().decryptWithAd(null, s2c, 0, plaintext, 0, s2c.length);
        //System.out.printf("init recv cipher: s2c msg %s\n", HexFormat.of().formatHex(message, 0, s2c.length)); 
        //System.out.printf("init decrypt plaintext: %s\n", HexFormat.of().formatHex(plaintext, 0, s2c_plen)); 

        initiator.destroy();
        initPair.destroy();

        long commTime = System.nanoTime();

        long elapsedHandshake = handshakeTime - startTime;
        long elapsedComm = commTime - handshakeTime;

        String result = "noise,client," + c2sFileName + "," + 
            handshake1_len + "," + handshake2_len + "," + 
            c2s_len + "," + c2s_msg.length + "," + 
            s2c.length + "," + s2c_plen  + "," + 
            elapsedHandshake + "," + elapsedComm
            ;


        socket.close();
        return result;
    }

    private static String startServer(int port, String s2cFileName) throws Exception  {

        long startTime = System.nanoTime();

        ServerSocket server = new ServerSocket(port);
        try( Socket socket = server.accept()) {

            String protocolName = "Noise_KK_P256_AESGCM_SHA256";


            byte[] resp_prologue = HexFormat.of().parseHex("50726f6c6f677565313233");
            byte[] resp_static = HexFormat.of().parseHex("F9BA7BF2E14B0FC78888E36CA34D8E0E4798FEFA0F34A0F0C84037665DDD1DFB");
            byte[] resp_remote_static = HexFormat.of().parseHex("03579E25CF0C6D9782B9A2F61A56094538993AF1F79978B533157617D2A2EADF20");


            HandshakeState responder = new HandshakeState(protocolName, HandshakeState.RESPONDER);

            responder.setPrologue(resp_prologue, 0, resp_prologue.length);
            responder.getLocalKeyPair().setPrivateKey(resp_static, 0);
            responder.getRemotePublicKey().setPublicKey(resp_remote_static, 0);


            responder.start();

            byte[] message = new byte [1200000];
            byte[] plaintext = new byte [1200000];

            InputStream is = new BufferedInputStream(socket.getInputStream());
            OutputStream os = new BufferedOutputStream(socket.getOutputStream());

            int handshake1_len = is.read(message);
            int handshake1_plen = responder.readMessage(message, 0, handshake1_len, plaintext, 0);
            //System.out.printf("resp recv Handshake1: %s\n", HexFormat.of().formatHex(message,0, handshake1_len));

            int handshake2_len = responder.writeMessage(message, 0, null, 0, 0);
            os.write(message, 0, handshake2_len);
            os.flush();
            //System.out.printf("resp send handshake2: %s\n", HexFormat.of().formatHex(message,0, handshake2_len));

            //System.out.printf("resp handshake hash: %s\n", HexFormat.of().formatHex(responder.getHandshakeHash(), 0, responder.getHandshakeHash().length)); 

            CipherStatePair respPair;

            respPair = responder.split();

            long handshakeTime = System.nanoTime();

            //int c2s_len = is.read(message);
            byte[] c2s = readLargeInputStream(is);
            int c2s_plen = respPair.getReceiver().decryptWithAd(null, c2s, 0, plaintext, 0, c2s.length);
            //System.out.printf("resp recv cipher: c2s msg %s\n", HexFormat.of().formatHex(message, 0, c2s.length)); 
            //System.out.printf("recp decrypt plaintext: %s\n", HexFormat.of().formatHex(plaintext, 0, c2s_plen)); 

            byte[] s2c_msg =  Files.readAllBytes(Paths.get(s2cFileName));
            byte[] s2c_cipher = new byte[s2c_msg.length+16];
            int s2c_len = respPair.getSender().encryptWithAd(null, s2c_msg, 0, s2c_cipher, 0, s2c_msg.length);
            os.write(s2c_cipher, 0, s2c_len);
            os.flush();
            //System.out.printf("resp send cipher: s2c msg %s\n", HexFormat.of().formatHex(message, 0, s2c_len)); 
            //System.out.printf("resp send plaintext: %s\n", HexFormat.of().formatHex(s2c_msg, 0, s2c_msg.length)); 

            responder.destroy();
            respPair.destroy();

            long commTime = System.nanoTime();

            long elapsedHandshake = handshakeTime - startTime;
            long elapsedComm = commTime - handshakeTime;

            String result = "noise,server," + s2cFileName + "," + 
                handshake1_len + "," + handshake2_len + "," + 
                c2s.length + "," + c2s_plen + "," + 
                s2c_len + "," + s2c_msg.length  + "," + 
                elapsedHandshake + "," + elapsedComm
                ;


            socket.close();
            return result;
        }
    }

    public static void main(String[] args) throws Exception {
        String c2sFileName = args[0];
        String s2cFileName = args[1];

        Thread serverThread = new Thread(() -> {
            try {
                String res=startServer(63333, s2cFileName);
                System.out.println(res);
            }catch(Exception e){
                System.out.println(e);
            }
        });

        Thread clientThread = new Thread(() -> {
            try{
                String res = startClient("127.0.0.1", 63333, c2sFileName);
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
