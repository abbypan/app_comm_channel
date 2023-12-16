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
import java.security.KeyStore;
import java.security.SecureRandom;


import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import javax.net.ssl.*;
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

import org.apache.http.util.ByteArrayBuffer;




import java.nio.file.Files;
import java.nio.file.Paths;



public class runTLSEcho {
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

    public static String readLargeInputStreamString(InputStream is) throws Exception {
            long len = 0L;
            byte[] data = new byte[1200000];
            String PONG = "";
            while (true) {
                int readN = is.read(data);
                if (-1 == readN) {
                    break;
                }
                //System.out.println("read from buffer " + readN);
                len += readN;
                String rs = new String(data, 0, readN);
                PONG = PONG + rs;
            }
            return PONG;
    }

    public static String startClient(String host, int port, String c2sFileName) throws Exception {

        long startTime = System.nanoTime();

        KeyStore kStore = KeyStore.getInstance("PKCS12"); 
        kStore.load(new FileInputStream("continuity/clientkeystore.p12"), "cccccc".toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(kStore, "cccccc".toCharArray());
        KeyManager[] kms = kmf.getKeyManagers();

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream("continuity/clienttruststore.jks"), "cccccc".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        TrustManager[] tms = tmf.getTrustManagers();

        SSLContext sslContext = null;
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kms, tms, new SecureRandom());

        SocketFactory factory = sslContext.getSocketFactory();

        //SocketFactory factory = SSLSocketFactory.getDefault();
        try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {

            socket.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" });
            socket.setEnabledProtocols(new String[] { "TLSv1.3" });

            long handshakeTime = System.nanoTime();

            //System.out.println("sending message: " + PING);
            OutputStream os = new BufferedOutputStream(socket.getOutputStream());
            String PING =  new String(Files.readAllBytes(Paths.get(c2sFileName)));
            os.write(PING.getBytes());
            os.flush();
            socket.shutdownOutput();

            InputStream is = new BufferedInputStream(socket.getInputStream());
            byte[] PONG = readLargeInputStream(is);


            long commTime = System.nanoTime();

            long elapsedHandshake = handshakeTime - startTime;
            long elapsedComm = commTime - handshakeTime;

            String result = "continuity,client," + c2sFileName + "," + 
                PING.length() + "," +
                PONG.length + "," + 
                elapsedHandshake + "," + elapsedComm
                ;

            return result;
        }
    }

    public static String startServer(int port, String s2cFileName) throws Exception {

        long startTime = System.nanoTime();

        KeyStore kStore = KeyStore.getInstance("PKCS12"); 
        kStore.load(new FileInputStream("continuity/serverkeystore.p12"), "ssssss".toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(kStore, "ssssss".toCharArray());
        KeyManager[] kms = kmf.getKeyManagers();

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream("continuity/servertruststore.jks"), "ssssss".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        TrustManager[] tms = tmf.getTrustManagers();

        SSLContext sslContext = null;
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kms, tms, new SecureRandom());

        ServerSocketFactory factory = sslContext.getServerSocketFactory();

        //ServerSocketFactory factory = SSLServerSocketFactory.getDefault();
        try (SSLServerSocket listener = (SSLServerSocket) factory.createServerSocket(port)) {
            listener.setNeedClientAuth(true);
            listener.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" });
            listener.setEnabledProtocols(new String[] { "TLSv1.3" });
            //System.out.println("listening for messages...");
            try (Socket socket = listener.accept()) {

            long handshakeTime = System.nanoTime();

            

            InputStream is = new BufferedInputStream(socket.getInputStream());
            OutputStream os = new BufferedOutputStream(socket.getOutputStream());


            byte[] PING = readLargeInputStream(is);


                //System.out.printf("server received %d bytes: %s%n", PING.length(), PING);

                String PONG =  new String(Files.readAllBytes(Paths.get(s2cFileName)));
                int pong_len = PONG.getBytes().length;
                os.write(PONG.getBytes(), 0, pong_len);
                os.flush();
                //socket.shutdownOutput();
                //System.out.printf("server send %d bytes: %s%n", pong_len, PONG);

                long commTime = System.nanoTime();

                long elapsedHandshake = handshakeTime - startTime;
                long elapsedComm = commTime - handshakeTime;

                String result = "continuity,server," + s2cFileName + "," + 
                    PING.length + "," +
                    PONG.length() + "," + 
                    elapsedHandshake + "," + elapsedComm
                    ;

                return result;
            }

        }
    }

    public static void main(String args[]) throws Exception {
        String c2sFileName = args[0];
        String s2cFileName = args[1];

        Thread serverThread = new Thread(() -> {
            try {
                String res=startServer(43333, s2cFileName);
                System.out.println(res);
            }catch(Exception e){
                System.out.println(e);
            }
        });

        Thread clientThread = new Thread(() -> {
            try{
                String res = startClient("127.0.0.1", 43333, c2sFileName);
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
