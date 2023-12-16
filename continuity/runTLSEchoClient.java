import java.io.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.SocketFactory;

import java.nio.file.Files;
import java.nio.file.Paths;



public class runTLSEchoClient {

    public static String startClient(String host, int port, String c2sFileName) throws IOException {
        long startTime = System.nanoTime();

        SocketFactory factory = SSLSocketFactory.getDefault();
        try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {

            socket.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" });
            socket.setEnabledProtocols(new String[] { "TLSv1.3" });

            long handshakeTime = System.nanoTime();

            //System.out.println("sending message: " + PING);
            OutputStream os = new BufferedOutputStream(socket.getOutputStream());
            String PING =  new String(Files.readAllBytes(Paths.get(c2sFileName)));
            os.write(PING.getBytes());
            os.flush();

            InputStream is = new BufferedInputStream(socket.getInputStream());

            byte[] data = new byte[1200000];
            int len = is.read(data);
            String PONG = new String(data, 0, len);

            //System.out.printf("client received %d bytes: %s%n", len, PONG);

            long commTime = System.nanoTime();

            long elapsedHandshake = handshakeTime - startTime;
            long elapsedComm = commTime - handshakeTime;

            String result = "continuity,client," + c2sFileName + "," + 
                PING.length() + "," +
                PONG.length() + "," + 
                elapsedHandshake + "," + elapsedComm
                ;

            return result;
        }
    }

    public static void main(String args[]) throws Exception {
        String c2sFileName = args[0];
        String res = startClient("127.0.0.1", 53333, c2sFileName);
        System.out.println(res);
    }
}
