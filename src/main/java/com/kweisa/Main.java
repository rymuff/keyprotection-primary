package com.kweisa;

import com.kweisa.primary.Primary;

import javax.bluetooth.LocalDevice;
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

        String serverUrl = null; //"btspp://ACED5CBCD4B3:3;authenticate=false;encrypt=false;master=false";

        if (serverUrl == null) {
            // Find Server
            ArrayList<RemoteDevice> remoteDevices = Primary.discoverRemoteDevice();
            for (int i = 0; i < remoteDevices.size(); i++) {
                System.out.printf("%d. %s", i, remoteDevices.get(i).getBluetoothAddress());
                try {
                    System.out.printf(" - %s%n", remoteDevices.get(i).getFriendlyName(false));
                } catch (IOException ignored) {
                }
            }
            System.out.print("Select remote device > ");
            RemoteDevice remoteDevice = remoteDevices.get(scanner.nextInt());

            // Find service
            ArrayList<String> serviceUrls = Primary.searchServerUrl(remoteDevice, uuid);

            for (int i = 0; i < serviceUrls.size(); i++) {
                System.out.printf("%d. %s\n", i, serviceUrls.get(i));
            }

            System.out.print("Select server URL > ");

            serverUrl = serviceUrls.get(scanner.nextInt());
        }
        System.out.println("\nConnecting to " + serverUrl);

        String id = "primary-device";
        String password = "password"; // = scanner.nextLine();

        // Connect Server
        ArrayList<Long> test = new ArrayList<>();
        for (int i = 0; i < 1; i++) {
            long startTime = System.currentTimeMillis();
            Primary primary = new Primary();
            // primary.loadFromLocal(password);
            // primary.loadFromServer(id, password);
            primary.loadFromSecondary(password);
//            primary.connect(serverUrl);
//            primary.authenticate();
            primary.close();
            test.add(System.currentTimeMillis() - startTime);
        }

        for (Long aLong : test) {
            System.out.print(aLong + " ");
        }
    }
}
