package com.kweisa.primary;


import retrofit2.Retrofit;
import retrofit2.converter.scalars.ScalarsConverterFactory;

import javax.bluetooth.*;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.microedition.io.Connector;
import javax.microedition.io.StreamConnection;
import javax.microedition.io.StreamConnectionNotifier;
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

    public static ArrayList<String> searchService(RemoteDevice remoteDevice, UUID serviceUUID) throws InterruptedException, BluetoothStateException {
        Object serviceSearchCompletedEvent = new Object();
        ArrayList<String> connectionUrls = new ArrayList<>();

        synchronized (serviceSearchCompletedEvent) {
            LocalDevice.getLocalDevice().getDiscoveryAgent().searchServices(new int[]{0x0100}, new UUID[]{serviceUUID}, remoteDevice, new DiscoveryListener() {
                @Override
                public void deviceDiscovered(RemoteDevice btDevice, DeviceClass cod) {

                }

                @Override
                public void servicesDiscovered(int transID, ServiceRecord[] serviceRecords) {
                    for (ServiceRecord serviceRecord : serviceRecords) {
                        connectionUrls.add(serviceRecord.getConnectionURL(ServiceRecord.NOAUTHENTICATE_NOENCRYPT, false));
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
        return connectionUrls;
    }

    private SecretKey deriveKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        return new SecretKeySpec(secretKeyFactory.generateSecret(keySpec).getEncoded(), "AES");
    }

    private byte[] decrypt(SecretKey secretKey, byte[] nonce, byte[] input) throws BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        return cipher.doFinal(input);
    }

    private void load(String password, byte[] salt, byte[] nonce, byte[] encrypted) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException {
        SecretKey secretKey = deriveKey(password, salt);
        byte[] decrypted = decrypt(secretKey, nonce, encrypted);

        // Convert byte to PrivateKey
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decrypted));

        // Load Certificate
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        certificate = certificateFactory.generateCertificate(new FileInputStream(new File("primary.cert")));
    }

    public void loadFromLocal(String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException {
        byte[] salt = readBytesFromFile(new File("local.salt"));
        byte[] nonce = readBytesFromFile(new File("local.nonce"));
        byte[] encrypted = readBytesFromFile(new File("local.key"));

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
        byte[] nonce = readBytesFromFile(new File("server.nonce"));
        byte[] encrypted = readBytesFromFile(new File("server.key"));

        load(password, salt, nonce, encrypted);
    }

    public void loadFromSecondary(String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException, InterruptedException {
//        String url = "btspp://404E36AB4606:5";

        final String SERVER_UUID = "0000110100001000800000805F9B34FB";
        final String SERVER_URL = "btspp://localhost:" + SERVER_UUID + ";name=PrimaryDevice";

        StreamConnectionNotifier streamConnectionNotifier = (StreamConnectionNotifier) Connector.open(SERVER_URL);
        StreamConnection streamConnection = streamConnectionNotifier.acceptAndOpen();
        ServerThread serverThread = new ServerThread(streamConnection);
        serverThread.start();
        serverThread.join();

        System.out.println(serverThread.getSalt());
        byte[] salt = readBytesFromFile(new File("secondary.salt"));
        System.out.println(Base64.getEncoder().encodeToString(salt));
//        byte[] nonce = readBytesFromFile(new File("secondary.nonce"));
//        byte[] encrypted = readBytesFromFile(new File("secondary.key"));
//
//        load(password, salt, nonce, encrypted);
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
            fileInputStream.close();
            throw new IOException();
        }
        fileInputStream.close();

        return bytes;
    }

    static class ServerThread extends Thread {
        StreamConnection streamConnection;
        BufferedReader bufferedReader;
        BufferedWriter bufferedWriter;

        String salt;

        ServerThread(StreamConnection streamConnection) {
            this.streamConnection = streamConnection;
        }

        void send(String message) throws IOException {
            bufferedWriter.write(message + "\n");
            bufferedWriter.flush();

            System.out.printf("[>] %s\n", message);
        }

        String receive() throws IOException {
            String message = bufferedReader.readLine();
            System.out.printf("[<] %s\n", message);

            return message;
        }

        @Override
        public void run() {
            try {
                bufferedReader = new BufferedReader(new InputStreamReader(streamConnection.openInputStream()));
                bufferedWriter = new BufferedWriter(new OutputStreamWriter(streamConnection.openOutputStream()));

                send("Hello, World!");
                salt = receive();

                close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        void close() throws IOException {
            bufferedReader.close();
            bufferedWriter.close();
            streamConnection.close();
        }

        String getSalt() {
            return salt;
        }
    }
}
