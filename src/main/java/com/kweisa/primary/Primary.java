package com.kweisa.primary;


import com.kweisa.primary.bluetooth.Connection;
import com.kweisa.primary.bluetooth.ServerConnection;
import com.kweisa.primary.crypto.Crypto;
import com.kweisa.primary.crypto.KeyParameterSpec;
import com.kweisa.primary.util.Util;
import com.kweisa.primary.web.SaltService;
import retrofit2.Retrofit;
import retrofit2.converter.scalars.ScalarsConverterFactory;

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
    private final UUID UUID;
    private Certificate certificate;
    private PrivateKey privateKey;
    private Connection connection;
    public Primary(javax.bluetooth.UUID UUID) {
        this.UUID = UUID;
    }

    public void connect(String connectionUrl) throws IOException {
        connection = new Connection(connectionUrl);
        connection.open();
    }

    public void close() throws IOException {
        connection.close();
    }

    public void load(Type TYPE, String id, String password) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, InvalidKeySpecException, IllegalBlockSizeException {
        switch (TYPE) {
            case LOCAL:
                loadFromLocal(password);
                break;
            case SERVER:
                loadFromServer(id, password);
                break;
            case SECONDARY:
                loadFromSecondary(password);
                break;
        }
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

    private void loadFromLocal(String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException {
        byte[] salt = Util.readBytesFromFile(new File("local.salt"));
        byte[] nonce = Util.readBytesFromFile(new File("local.nonce"));
        byte[] encrypted = Util.readBytesFromFile(new File("local.key"));

        load(password, salt, nonce, encrypted);
    }

    private void loadFromServer(String username, String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException {
        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("https://rymuff.com:8080")
                .addConverterFactory(ScalarsConverterFactory.create())
                .build();
        SaltService saltService = retrofit.create(SaltService.class);
        String encodedSalt = saltService.readSalt(username, password).execute().body();

        if (encodedSalt == null) {
            throw new NullPointerException();
        }

        byte[] salt = Base64.getUrlDecoder().decode(encodedSalt);
        byte[] nonce = Util.readBytesFromFile(new File("server.nonce"));
        byte[] encrypted = Util.readBytesFromFile(new File("server.key"));

        load(password, salt, nonce, encrypted);
    }

    private void loadFromSecondary(String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException {
        System.out.println("Waiting for connection");
        ServerConnection serverConnection = new ServerConnection(UUID);

        serverConnection.accept();
        serverConnection.send(password);
        String encodedSalt = serverConnection.receiveString();

        serverConnection.close();

        byte[] salt = Base64.getDecoder().decode(encodedSalt);
        byte[] nonce = Util.readBytesFromFile(new File("secondary.nonce"));
        byte[] encrypted = Util.readBytesFromFile(new File("secondary.key"));

        load(password, salt, nonce, encrypted);
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

    public void enroll(String username, String password) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, BadPaddingException {
        // Get private key
        long timer = System.currentTimeMillis();
        final byte[] salt = Util.readBytesFromFile(new File("local.salt"));
        final byte[] nonce = Util.readBytesFromFile(new File("local.nonce"));
        final byte[] encrypted = Util.readBytesFromFile(new File("local.key"));

        SecretKey secretKey = Crypto.deriveKey(password, salt);
        byte[] decrypted = Crypto.decrypt(secretKey, nonce, encrypted);

        // Enroll to server
        KeyParameterSpec serverKeyParameterSpec = new KeyParameterSpec(password, decrypted);

        Util.writeBytesToFile(new File("server.key"), serverKeyParameterSpec.getEncryptedPrivateKey());
        Util.writeBytesToFile(new File("server.nonce"), serverKeyParameterSpec.getNonce());

        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("https://rymuff.com:8080")
                .addConverterFactory(ScalarsConverterFactory.create())
                .build();
        SaltService saltService = retrofit.create(SaltService.class);
        saltService.createUser(username, password, Base64.getUrlEncoder().encodeToString(serverKeyParameterSpec.getSalt())).execute();

        // Enroll to secondary device
        KeyParameterSpec secondaryKeyParameterSpec = new KeyParameterSpec(password, decrypted);

        Util.writeBytesToFile(new File("secondary.key"), secondaryKeyParameterSpec.getEncryptedPrivateKey());
        Util.writeBytesToFile(new File("secondary.nonce"), secondaryKeyParameterSpec.getNonce());

        System.out.println("Waiting for connection");
        System.out.println(timer - System.currentTimeMillis());
        ServerConnection serverConnection = new ServerConnection(UUID);
        System.out.println(timer - System.currentTimeMillis());
        serverConnection.accept();
        serverConnection.send(password);
        serverConnection.send(Base64.getEncoder().encodeToString(secondaryKeyParameterSpec.getSalt()));
        serverConnection.close();
        System.out.println(timer - System.currentTimeMillis());
    }

    public enum Type {LOCAL, SERVER, SECONDARY}
}
