import java.io.*;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import java.nio.file.Files;
import java.nio.file.Paths;


public class runTLSEchoServer {

    public static String startServer(int port, String s2cFileName) throws IOException {
        long startTime = System.nanoTime();

        ServerSocketFactory factory = SSLServerSocketFactory.getDefault();
        try (SSLServerSocket listener = (SSLServerSocket) factory.createServerSocket(port)) {
            listener.setNeedClientAuth(true);
            listener.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" });
            listener.setEnabledProtocols(new String[] { "TLSv1.3" });
            //System.out.println("listening for messages...");
            try (Socket socket = listener.accept()) {

            long handshakeTime = System.nanoTime();

                InputStream is = new BufferedInputStream(socket.getInputStream());

                byte[] data = new byte[1200000];
                int len = is.read(data);
                String PING = new String(data, 0, len);

                //System.out.printf("server received %d bytes: %s%n", len, PING);

                String PONG =  new String(Files.readAllBytes(Paths.get(s2cFileName)));
                int pong_len = PONG.getBytes().length;
                OutputStream os = new BufferedOutputStream(socket.getOutputStream());
                os.write(PONG.getBytes(), 0, pong_len);
                os.flush();
                //System.out.printf("server send %d bytes: %s%n", pong_len, PONG);

            long commTime = System.nanoTime();

            long elapsedHandshake = handshakeTime - startTime;
            long elapsedComm = commTime - handshakeTime;

            String result = "continuity,server," + s2cFileName + "," + 
                PING.length() + "," +
                PONG.length() + "," + 
                elapsedHandshake + "," + elapsedComm
                ;

            return result;
            }

        }
    }

    public static void main(String args[]) throws Exception {
        String s2cFileName = args[0];
        String res=startServer(53333, s2cFileName);
        System.out.println(res);
    }
}

