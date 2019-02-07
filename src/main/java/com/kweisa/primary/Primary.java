package com.kweisa.primary;


import javax.bluetooth.*;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.microedition.io.Connector;
import javax.microedition.io.StreamConnection;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;

public class Primary {
    private Certificate certificate;
    private PrivateKey privateKey;
    private StreamConnection streamConnection;
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;

    public static ArrayList<RemoteDevice> discoverRemoteDevice() throws BluetoothStateException, InterruptedException {
        Object inquiryCompletedEvent = new Object();
        ArrayList<RemoteDevice> remoteDevices = new ArrayList<>();

        synchronized (inquiryCompletedEvent) {
            LocalDevice.getLocalDevice().getDiscoveryAgent().startInquiry(DiscoveryAgent.GIAC, new DiscoveryListener() {
                @Override
                public void deviceDiscovered(RemoteDevice btDevice, DeviceClass cod) {
                    remoteDevices.add(btDevice);
                }

                @Override
                public void servicesDiscovered(int transID, ServiceRecord[] serviceRecords) {
                }

                @Override
                public void serviceSearchCompleted(int transID, int respCode) {

                }

                @Override
                public void inquiryCompleted(int discType) {
                    synchronized (inquiryCompletedEvent) {
                        System.out.println("[inquiry completed]");
                        inquiryCompletedEvent.notifyAll();
                    }
                }
            });
            System.out.print("\nStart inquiry remote devices... ");
            inquiryCompletedEvent.wait();
        }
        return remoteDevices;
    }

    public static ArrayList<String> searchServerUrl(RemoteDevice remoteDevice, UUID serviceUUID) throws InterruptedException, BluetoothStateException {
        Object serviceSearchCompletedEvent = new Object();
        ArrayList<String> serviceUrls = new ArrayList<>();

        synchronized (serviceSearchCompletedEvent) {
            LocalDevice.getLocalDevice().getDiscoveryAgent().searchServices(null, new UUID[]{serviceUUID}, remoteDevice, new DiscoveryListener() {
                @Override
                public void deviceDiscovered(RemoteDevice btDevice, DeviceClass cod) {

                }

                @Override
                public void servicesDiscovered(int transID, ServiceRecord[] serviceRecords) {
                    for (ServiceRecord serviceRecord : serviceRecords) {
                        serviceUrls.add(serviceRecord.getConnectionURL(ServiceRecord.NOAUTHENTICATE_NOENCRYPT, false));
                    }
                }

                @Override
                public void serviceSearchCompleted(int transID, int respCode) {
                    synchronized (serviceSearchCompletedEvent) {
                        System.out.println("[service search completed]");
                        serviceSearchCompletedEvent.notifyAll();
                    }
                }

                @Override
                public void inquiryCompleted(int discType) {

                }
            });
            System.out.print("\nSearch services... ");
            serviceSearchCompletedEvent.wait();
        }
        return serviceUrls;
    }

    public void load(String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException {
        final byte[] salt = readBytesFromFile(new File("salt"));
        final byte[] nonce = readBytesFromFile(new File("nonce"));
        final byte[] encrypted = readBytesFromFile(new File("private.key"));

        // DERIVE key (from password and salt)
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        KeySpec passwordBasedEncryptionKeySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKey secretKeyFromPBKDF2 = secretKeyFactory.generateSecret(passwordBasedEncryptionKeySpec);
        SecretKey key = new SecretKeySpec(secretKeyFromPBKDF2.getEncoded(), "AES");

        // DECRYPTION
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        byte[] decrypted = cipher.doFinal(encrypted);

        // Convert byte to PrivateKey
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decrypted));

        // Load Certificate
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        certificate = certificateFactory.generateCertificate(new FileInputStream(new File("primary.cert")));
    }

    public void connect(String serverUrl) throws IOException {
        streamConnection = (StreamConnection) Connector.open(serverUrl);
        bufferedReader = new BufferedReader(new InputStreamReader(streamConnection.openInputStream()));
        bufferedWriter = new BufferedWriter(new OutputStreamWriter(streamConnection.openOutputStream()));
    }

    public void authenticate() throws CertificateEncodingException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Send certificate
        send(certificate.getEncoded());

        // Receive nonce
        byte[] nonce = receive();

        // Sign nonce, and send signature
        byte[] signature = sign(nonce);
        send(signature);

        // Receive result
        if (receiveInt() == 0) {
            System.out.println("[*] Verified");
        } else {
            System.out.println("[*] Verified fail");
        }
    }

    private byte[] sign(byte[] message) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message);

        return signature.sign();
    }

    private void send(byte[] data) throws IOException {
        String message = Base64.getEncoder().encodeToString(data);

        bufferedWriter.write(message + "\n");
        bufferedWriter.flush();

        System.out.printf("[>] %s\n", message);
    }

    private byte[] receive() throws IOException {
        String message = bufferedReader.readLine();
        System.out.printf("[<] %s\n", message);

        return Base64.getDecoder().decode(message);
    }

    private int receiveInt() throws IOException {
        int data = bufferedReader.read();
        System.out.printf("[<] INT:%d\n", data);

        return data;
    }

    public void close() throws IOException {
        bufferedReader.close();
        bufferedWriter.close();
        streamConnection.close();
    }

    private static byte[] readBytesFromFile(File file) throws IOException {
        FileInputStream fileInputStream = new FileInputStream(file);
        byte[] bytes = new byte[fileInputStream.available()];
        if (fileInputStream.available() != fileInputStream.read(bytes)) {
            throw new IOException();
        }
        return bytes;
    }
}
