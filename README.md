# app_comm_channel

# install
    
      $ apt install default-jre default-jdk openssl 
      $ apt install cpanminus libcrypt-openssl-ec-perl libcrypt-openssl-bignum-perl 
      $ cpanm Crypt::OpenSSL::Base::Func

## jar

ukey2: https://github.com/abbypan/ukey2_java

noise: https://github.com/abbypan/noise-java/

httpcore: https://hc.apache.org/index.html

## experiment
    
    $ perl exp.pl

# key derivation
   
    $ cd key_derivation
    $ perl key_derivation.pl upsk
    $ perl key_derivation.pl ud
    $ perl key_derivation.pl udpub
    $ perl key_derivation.pl uc
    $ perl key_derivation.pl ucpub

# test noise

    $ java -cp resources/httpcore-4.4.16.jar:noise/noise-java-1.0-SNAPSHOT.jar noise/runNoiseNNpsk.java resources/c2s.txt resources/s2c.txt
    $ java -cp resources/httpcore-4.4.16.jar:noise/noise-java-1.0-SNAPSHOT.jar noise/runNoiseXKpsk.java resources/c2s.txt resources/s2c.txt
    $ java -cp resources/httpcore-4.4.16.jar:noise/noise-java-1.0-SNAPSHOT.jar noise/runNoiseXX.java resources/c2s.txt resources/s2c.txt

# test ukey2

    $ java -cp resources/httpcore-4.4.16.jar:ukey2/ukey2_java_shadow.jar ukey2/runUkey2.java resources/c2s.txt resources/s2c.txt

# test continuity (mutual tls)

prepare:

    $ keytool -genkey -alias serverkey -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA -keystore serverkeystore.p12 -storepass ssssss -ext san=ip:127.0.0.1,dns:localhost
    $ keytool -exportcert -keystore serverkeystore.p12 -alias serverkey -storepass ssssss -rfc -file server-certificate.pem
    $ keytool -import -trustcacerts -file server-certificate.pem -keypass password -storepass cccccc -keystore clienttruststore.jks

    $ keytool -genkey -alias clientkey -keyalg EC -groupname secp256r1  -sigalg SHA256withECDSA -keystore clientkeystore.p12 -storepass cccccc -ext san=ip:127.0.0.1,dns:localhost
    $ keytool -exportcert -keystore clientkeystore.p12 -alias clientkey -storepass cccccc -rfc -file client-certificate.pem
    $ keytool -import -trustcacerts -file client-certificate.pem -keypass password -storepass ssssss -keystore servertruststore.jks

test:

    $ java -cp resources/httpcore-4.4.16.jar continuity/runTLSEcho.java resources/c2s.txt resources/s2c.txt

test with client and server:

    $ java -Djavax.net.ssl.keyStore=continuity/serverkeystore.p12 -Djavax.net.ssl.keyStorePassword=ssssss -Djavax.net.ssl.trustStore=continuity/servertruststore.jks -Djavax.net.ssl.trustStorePassword=ssssss  continuity/runTLSEchoServer.java resources/s2c.txt 
    $ java -Djavax.net.ssl.keyStore=continuity/clientkeystore.p12 -Djavax.net.ssl.keyStorePassword=cccccc -Djavax.net.ssl.trustStore=continuity/clienttruststore.jks -Djavax.net.ssl.trustStorePassword=cccccc  continuity/runTLSEchoClient.java resources/c2s.txt

test with debug, use tshark capture packets:

    # tshark -f "tcp port 53333" -i any -w a.cap
    $ java -Djavax.net.ssl.keyStore=continuity/serverkeystore.p12 -Djavax.net.ssl.keyStorePassword=ssssss -Djavax.net.ssl.trustStore=continuity/servertruststore.jks -Djavax.net.ssl.trustStorePassword=ssssss  -Djavax.net.debug=ssl:record continuity/runTLSEchoServer.java resources/s2c.txt | tee data/continuity_s2c.log
    $ java -Djavax.net.ssl.keyStore=continuity/clientkeystore.p12 -Djavax.net.ssl.keyStorePassword=cccccc -Djavax.net.ssl.trustStore=continuity/clienttruststore.jks -Djavax.net.ssl.trustStorePassword=cccccc  -Djavax.net.debug=ssl:record continuity/runTLSEchoClient.java resources/c2s.txt | tee data/continuity_c2s.log

