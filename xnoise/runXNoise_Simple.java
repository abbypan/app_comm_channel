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

public class runXNoise {

    private static String runTest(String c2sFileName, String s2cFileName) throws Exception  {

        long startTime = System.nanoTime();

        String protocolName = "Noise_KK-KK_P256_AESGCM_SHA256";

        byte[] init_prologue = HexFormat.of().parseHex("50726f6c6f677565313233");
        byte[] init_static = HexFormat.of().parseHex("6C01E03D2669C921D172F49E7DDB04625A7391227B99BB08979D7AA4884056AA");
        byte[] init_staticm = HexFormat.of().parseHex("27B8046DCB1770EEBE55DC0F44B5DC38070D85D4AB08810D318CF960E5C90AB6");
        byte[] init_remote_static = HexFormat.of().parseHex("034BF8F658E2039CE631A3F28F78418A004DE061A3DD50E8896610C3A2BB4C77CC");
        byte[] init_remote_staticm = HexFormat.of().parseHex("0364884304A5801E8B7A6566D50D9E66CFA60EE9099E35CA2BFBCD70BA3EBD966F");
        //byte[] init_ephemeral = HexFormat.of().parseHex("6c01e03d2669c921d172f49e7ddb04625a7391227b99bb08979d7aa4884056aa");


        byte[] resp_prologue = HexFormat.of().parseHex("50726f6c6f677565313233");
        byte[] resp_static = HexFormat.of().parseHex("F9BA7BF2E14B0FC78888E36CA34D8E0E4798FEFA0F34A0F0C84037665DDD1DFB");
        byte[] resp_staticm = HexFormat.of().parseHex("01A21A9D21732D3491FD9D3F028EE0DD872C477B5CE6FD14A1637A2E391991E9");
        byte[] resp_remote_static = HexFormat.of().parseHex("03579E25CF0C6D9782B9A2F61A56094538993AF1F79978B533157617D2A2EADF20");
        byte[] resp_remote_staticm = HexFormat.of().parseHex("03A1C8356996505F27A35700B4AB073482F06C8F9D336C253C7B510AF2E3FD2949");
        //byte[] resp_ephemeral = HexFormat.of().parseHex("f9ba7bf2e14b0fc78888e36ca34d8e0e4798fefa0f34a0f0c84037665ddd1dfb");


        HandshakeState initiator = new HandshakeState(protocolName, HandshakeState.INITIATOR);
        HandshakeState responder = new HandshakeState(protocolName, HandshakeState.RESPONDER);

        initiator.setPrologue(init_prologue, 0, init_prologue.length);
        initiator.getLocalKeyPair().setPrivateKey(init_static, 0);
        initiator.getLocalKeyPairM().setPrivateKey(init_staticm, 0);
        initiator.getRemotePublicKey().setPublicKey(init_remote_static, 0);
        initiator.getRemotePublicKeyM().setPublicKey(init_remote_staticm, 0);
        //initiator.getFixedEphemeralKey().setPrivateKey(init_ephemeral, 0);

        responder.setPrologue(resp_prologue, 0, resp_prologue.length);
        responder.getLocalKeyPair().setPrivateKey(resp_static, 0);
        responder.getLocalKeyPairM().setPrivateKey(resp_staticm, 0);
        responder.getRemotePublicKey().setPublicKey(resp_remote_static, 0);
        responder.getRemotePublicKeyM().setPublicKey(resp_remote_staticm, 0);
        //responder.getFixedEphemeralKey().setPrivateKey(resp_ephemeral, 0);


        initiator.start();
        responder.start();

        byte[] message = new byte [1200000];
        byte[] plaintext = new byte [1200000];

        //System.out.println("Handshake: e, es, ss, em, mm");
        //byte[] init_hello = HexFormat.of().parseHex("4c756477696720766f6e204d69736573");
        //int handshake1_len = initiator.writeMessage(message, 0, init_hello, 0, init_hello.length);
        int handshake1_len = initiator.writeMessage(message, 0, null, 0, 0);
        int plen = responder.readMessage(message, 0, handshake1_len, plaintext, 0);
        //System.out.printf("init -> resp: %s\n", HexFormat.of().formatHex(message,0, handshake1_len));
        //System.out.printf("init send hello: %s\n", HexFormat.of().formatHex(init_hello, 0, init_hello.length));
        //System.out.printf("resp read hello: %s\n", HexFormat.of().formatHex(plaintext, 0, plen));

        //System.out.println("Handshake: e, ee, se, me");
        //byte[] resp_hello = HexFormat.of().parseHex("4d757272617920526f746862617264");
        //int handshake2_len = responder.writeMessage(message, 0, resp_hello, 0, resp_hello.length);
        int handshake2_len = responder.writeMessage(message, 0, null, 0, 0);
        plen = initiator.readMessage(message, 0, handshake2_len, plaintext, 0);
        //System.out.printf("resp -> init: %s\n", HexFormat.of().formatHex(message,0, handshake2_len));
        //System.out.printf("resp send hello: %s\n", HexFormat.of().formatHex(resp_hello, 0, resp_hello.length));
        //System.out.printf("init read hello: %s\n", HexFormat.of().formatHex(plaintext, 0, plen));


        //System.out.printf("init handshake hash: %s\n", HexFormat.of().formatHex(initiator.getHandshakeHash(), 0, initiator.getHandshakeHash().length)); 
        //System.out.printf("resp handshake hash: %s\n", HexFormat.of().formatHex(responder.getHandshakeHash(), 0, responder.getHandshakeHash().length)); 

        CipherStatePair initPair;
        CipherStatePair respPair;

        initPair = initiator.split();
        respPair = responder.split();

        long handshakeTime = System.nanoTime();

        //byte[] c2s_msg = HexFormat.of().parseHex("462e20412e20486179656b");
        byte[] c2s_msg =  Files.readAllBytes(Paths.get(c2sFileName));
        int c2s_len = initPair.getSender().encryptWithAd(null, c2s_msg, 0, message, 0, c2s_msg.length);
        plen = respPair.getReceiver().decryptWithAd(null, message, 0, plaintext, 0, c2s_len);
        //System.out.printf("init->resp: c2s msg %s\n", HexFormat.of().formatHex(message, 0, c2s_len)); 
        //System.out.printf("init plaintext: %s\n", HexFormat.of().formatHex(c2s_msg, 0, c2s_msg.length)); 
        //System.out.printf("recp plaintext: %s\n", HexFormat.of().formatHex(plaintext, 0, plen)); 

        //byte[] s2c_msg = HexFormat.of().parseHex("4361726c204d656e676572");
        byte[] s2c_msg =  Files.readAllBytes(Paths.get(s2cFileName));
        int s2c_len = respPair.getSender().encryptWithAd(null, s2c_msg, 0, message, 0, s2c_msg.length);
        plen = initPair.getReceiver().decryptWithAd(null, message, 0, plaintext, 0, s2c_len);
        //System.out.printf("resp->init: s2c msg %s\n", HexFormat.of().formatHex(message, 0, s2c_len)); 
        //System.out.printf("resp plaintext: %s\n", HexFormat.of().formatHex(s2c_msg, 0, s2c_msg.length)); 
        //System.out.printf("init plaintext: %s\n", HexFormat.of().formatHex(plaintext, 0, plen)); 

        initiator.destroy();
        responder.destroy();
        initPair.destroy();
        respPair.destroy();

        long commTime = System.nanoTime();

        long elapsedHandshake = handshakeTime - startTime;
        long elapsedComm = commTime - handshakeTime;

        String result = "xnoise," + c2sFileName + "," + s2cFileName + "," + 
            handshake1_len + "," + handshake2_len + "," + 
            c2s_len + "," + c2s_msg.length + "," + 
            s2c_len + "," + s2c_msg.length  + "," + 
            elapsedHandshake + "," + elapsedComm
            ;


        return result;
    }

    public static void main(String[] args) throws Exception {
        String c2sFileName = args[0];
        String s2cFileName = args[1];

        String res = runTest(c2sFileName, s2cFileName);
        System.out.println(res);
    }
}
