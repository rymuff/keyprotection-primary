package com.kweisa;

import com.kweisa.primary.Primary;

import javax.bluetooth.RemoteDevice;
import javax.bluetooth.UUID;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, InvalidKeySpecException, IllegalBlockSizeException, SignatureException, InterruptedException {
        Scanner scanner = new Scanner(System.in);

        UUID uuid = new UUID("0000110100001000800000805F9B34FB", false);

        // Find server
        ArrayList<RemoteDevice> remoteDevices = Primary.discoverRemoteDevice();
        for (int i = 0; i < remoteDevices.size(); i++) {
            System.out.printf("%d. %s", i, remoteDevices.get(i).getBluetoothAddress());
            try {
                System.out.printf(" - %s%n", remoteDevices.get(i).getFriendlyName(false));
            } catch (IOException ignored) {
            }
        }

        // Select server
        System.out.print("Select remote device > ");

        RemoteDevice remoteDevice;
        if (remoteDevices.size() == 0) {
            System.out.println("NOT FOUND");
            return;
        } else if (remoteDevices.size() == 1) {
            System.out.println("0");
            remoteDevice = remoteDevices.get(0);
        } else {
            remoteDevice = remoteDevices.get(scanner.nextInt());
        }

        // Find service
        ArrayList<String> connectionUrls = Primary.searchService(remoteDevice, uuid);

        for (int i = 0; i < connectionUrls.size(); i++) {
            System.out.printf("%d. %s\n", i, connectionUrls.get(i));
        }

        // Select service
        System.out.print("Select connection URL > ");

        String serverUrl;
        if (connectionUrls.size() == 0) {
            System.out.println("NOT FOUND");
            return;
        } else if (connectionUrls.size() == 1) {
            serverUrl = connectionUrls.get(0);
        } else {
            serverUrl = connectionUrls.get(scanner.nextInt());
        }

        System.out.println("\nConnecting to " + serverUrl);

        String id = "primary-device"; // = scanner.nextLine();
        String password = "password"; // = scanner.nextLine();

        // Connect Server
        ArrayList<Long> test = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            long startTime = System.currentTimeMillis();
            Primary primary = new Primary();
            // primary.loadFromLocal(password);
            // primary.loadFromServer(id, password);
            startTime = startTime - primary.loadFromSecondary(password);
            primary.connect(serverUrl);
            primary.authenticate();
            primary.close();
            test.add(System.currentTimeMillis() - startTime);
        }

        for (Long aLong : test) {
            System.out.print(aLong + " ");
        }
    }
}
