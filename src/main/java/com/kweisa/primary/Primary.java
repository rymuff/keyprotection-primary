package com.kweisa.primary;


import com.kweisa.primary.bluetooth.Connection;
import com.kweisa.primary.bluetooth.DiscoverAgent;
import com.kweisa.primary.bluetooth.ServerConnection;
import com.kweisa.primary.crypto.Crypto;
import com.kweisa.primary.util.Util;
import com.kweisa.primary.web.SaltService;
import retrofit2.Retrofit;
import retrofit2.converter.scalars.ScalarsConverterFactory;

import javax.bluetooth.DiscoveryAgent;
import javax.bluetooth.LocalDevice;
import javax.bluetooth.UUID;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class Primary {
    private static final UUID UUID = new UUID("0000110100001000800000805F9B34FB", false);

    private Certificate certificate;
    private PrivateKey privateKey;
    private Connection connection;

    public void connect(String connectionUrl) throws IOException {
        connection = new Connection(connectionUrl);
        connection.open();
    }

    public void close() throws IOException {
        connection.close();
    }

    private void load(String password, byte[] salt, byte[] nonce, byte[] encrypted) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException {
        SecretKey secretKey = Crypto.deriveKey(password, salt);
        byte[] decrypted = Crypto.decrypt(secretKey, nonce, encrypted);

        // Convert byte to PrivateKey
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decrypted));

        // Load Certificate
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        certificate = certificateFactory.generateCertificate(new FileInputStream(new File("primary.cert")));
    }

    public void loadFromLocal(String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException {
        byte[] salt = Util.readBytesFromFile(new File("local.salt"));
        byte[] nonce = Util.readBytesFromFile(new File("local.nonce"));
        byte[] encrypted = Util.readBytesFromFile(new File("local.key"));

        load(password, salt, nonce, encrypted);
    }

    public void loadFromServer(String id, String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException {
        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("http://rymuff.com")
                .addConverterFactory(ScalarsConverterFactory.create())
                .build();
        SaltService saltService = retrofit.create(SaltService.class);
        String encodedSalt = saltService.readSalt(id, password).execute().body();

        if (encodedSalt == null) {
            throw new NullPointerException();
        }

        byte[] salt = Base64.getUrlDecoder().decode(encodedSalt);
        byte[] nonce = Util.readBytesFromFile(new File("server.nonce"));
        byte[] encrypted = Util.readBytesFromFile(new File("server.key"));

        load(password, salt, nonce, encrypted);
    }

    public long loadFromSecondary(String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException, InterruptedException {
        System.out.println("Waiting for connection");
        ServerConnection serverConnection = new ServerConnection(UUID);

        long time = System.currentTimeMillis();

        serverConnection.accept();

        time = time - System.currentTimeMillis();

        serverConnection.send(password);
        String encodedSalt = serverConnection.receiveString();

        serverConnection.close();

        byte[] salt = Base64.getDecoder().decode(encodedSalt);
        byte[] nonce = Util.readBytesFromFile(new File("secondary.nonce"));
        byte[] encrypted = Util.readBytesFromFile(new File("secondary.key"));

        load(password, salt, nonce, encrypted);

        return time;
    }


    public void authenticate() throws CertificateEncodingException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Send certificate
        connection.send(certificate.getEncoded());

        // Receive nonce
        byte[] nonce = connection.receiveEncoded();

        // Sign nonce, and send signature
        byte[] signature = Crypto.sign(nonce, privateKey);
        connection.send(signature);

        // Receive result
        if (connection.receiveInt() == 0) {
            System.out.println("[*] Verified");
        } else {
            System.out.println("[*] Verified fail");
        }
    }

    public void enroll(String id, String password) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, BadPaddingException {
        final byte[] salt = Util.readBytesFromFile(new File("local.salt"));
        final byte[] nonce = Util.readBytesFromFile(new File("local.nonce"));
        final byte[] encrypted = Util.readBytesFromFile(new File("local.key"));

        SecretKey localKey = Crypto.deriveKey(password, salt);
        byte[] decrypted = Crypto.decrypt(localKey, nonce, encrypted);
        Util.writeBytesToFile(new File("private.key"), decrypted);

        byte[] serverSalt = Crypto.generateRandomBytes(64);
        byte[] serverNonce = Crypto.generateRandomBytes(32);

        SecretKey serverKey = Crypto.deriveKey(password, serverSalt);
        byte[] serverEncrypted = Crypto.encrypt(serverKey, serverNonce, decrypted);

        Util.writeBytesToFile(new File("server.key"), serverEncrypted);
        Util.writeBytesToFile(new File("server.nonce"), serverNonce);

        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("http://rymuff.com")
                .addConverterFactory(ScalarsConverterFactory.create())
                .build();
        SaltService saltService = retrofit.create(SaltService.class);
        saltService.createUser(id, password, Base64.getUrlEncoder().encodeToString(serverSalt)).execute();

        byte[] secondarySalt = Crypto.generateRandomBytes(64);
        byte[] secondaryNonce = Crypto.generateRandomBytes(32);

        SecretKey secondaryKey = Crypto.deriveKey(password, secondarySalt);

        byte[] secondaryEncrypted = Crypto.encrypt(secondaryKey, secondaryNonce, decrypted);
        Util.writeBytesToFile(new File("secondary.key"), secondaryEncrypted);
        Util.writeBytesToFile(new File("secondary.nonce"), secondaryNonce);

        ServerConnection serverConnection = new ServerConnection(UUID);
        serverConnection.accept();
        serverConnection.send(password);
        serverConnection.send(Base64.getEncoder().encodeToString(secondarySalt));
        serverConnection.close();
    }


    public static void main(String[] args) throws Exception {
        LocalDevice.getLocalDevice().setDiscoverable(DiscoveryAgent.GIAC);
//        RemoteDevice remoteDevice = DiscoverAgent.selectRemoteDevice();
//        String connectionUrl = DiscoverAgent.selectConnectionUrl(remoteDevice, UUID);
//
//        System.out.println("\nConnecting to " + connectionUrl);

        System.out.println("Hi");
        String id = "primary-device"; // = scanner.nextLine();
        String password = "password"; // = scanner.nextLine();

        Primary primary = new Primary();
        primary.enroll(id, password);

//        // Connect Server
//        ArrayList<Long> test = new ArrayList<>();
//        for (int i = 0; i < 100; i++) {
//            long startTime = System.currentTimeMillis();
//            Primary primary = new Primary();
//            primary.loadFromLocal(password);
//            // primary.loadFromServer(id, password);
////            startTime = startTime - primary.loadFromSecondary(password);
//            primary.connect(connectionUrl);
//            primary.authenticate();
//            primary.close();
//            test.add(System.currentTimeMillis() - startTime);
//        }
//
//        for (Long aLong : test) {
//            System.out.print(aLong + " ");
//        }
    }
}
