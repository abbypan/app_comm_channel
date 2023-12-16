
keytool -genkey -alias serverkey -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA -keystore serverkeystore.p12 -storepass ssssss -ext san=ip:127.0.0.1,dns:localhost
keytool -exportcert -keystore serverkeystore.p12 -alias serverkey -storepass ssssss -rfc -file server-certificate.pem
keytool -import -trustcacerts -file server-certificate.pem -keypass password -storepass cccccc -keystore clienttruststore.jks

keytool -genkey -alias clientkey -keyalg EC -groupname secp256r1  -sigalg SHA256withECDSA -keystore clientkeystore.p12 -storepass cccccc -ext san=ip:127.0.0.1,dns:localhost
keytool -exportcert -keystore clientkeystore.p12 -alias clientkey -storepass cccccc -rfc -file client-certificate.pem
keytool -import -trustcacerts -file client-certificate.pem -keypass password -storepass ssssss -keystore servertruststore.jks

java -Djavax.net.ssl.keyStore=serverkeystore.p12 -Djavax.net.ssl.keyStorePassword=ssssss -Djavax.net.ssl.trustStore=servertruststore.jks -Djavax.net.ssl.trustStorePassword=ssssss -Djavax.net.debug=ssl:record runTLSEchoServer.java s2c.txt | tee s2c.log
java -Djavax.net.ssl.keyStore=clientkeystore.p12 -Djavax.net.ssl.keyStorePassword=cccccc -Djavax.net.ssl.trustStore=clienttruststore.jks -Djavax.net.ssl.trustStorePassword=cccccc -Djavax.net.debug=ssl:record runTLSEchoClient.java c2s.txt | tee c2s.log
tshark -f "tcp port 53333" -i any -w a.cap

java -Djavax.net.ssl.keyStore=serverkeystore.p12 -Djavax.net.ssl.keyStorePassword=ssssss -Djavax.net.ssl.trustStore=servertruststore.jks -Djavax.net.ssl.trustStorePassword=ssssss  runTLSEchoServer.java s2c.txt | tee s2c.log
java -Djavax.net.ssl.keyStore=clientkeystore.p12 -Djavax.net.ssl.keyStorePassword=cccccc -Djavax.net.ssl.trustStore=clienttruststore.jks -Djavax.net.ssl.trustStorePassword=cccccc  runTLSEchoClient.java c2s.txt | tee c2s.log
