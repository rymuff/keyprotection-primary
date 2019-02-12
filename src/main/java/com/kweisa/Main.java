package com.kweisa;

import com.kweisa.primary.Primary;
import com.kweisa.primary.bluetooth.DiscoverAgent;

import javax.bluetooth.RemoteDevice;
import javax.bluetooth.UUID;
import java.util.Scanner;

public class Main {
    private static final javax.bluetooth.UUID UUID = new UUID("0000110100001000800000805F9B34FB", false);

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.println("1. Enroll as new device");
        System.out.println("2. Connect to the controller");
        System.out.print("> ");
        int choice = scanner.nextInt();

        System.out.print("Username> ");
        String username = scanner.nextLine(); // primary-device
        System.out.print("Password> ");
        String password = scanner.nextLine(); // password

        Primary primary = new Primary(UUID);

        if (choice == 1) {
            primary.enroll(username, password);
        } else {
            RemoteDevice remoteDevice = DiscoverAgent.selectRemoteDevice();
            String connectionUrl = DiscoverAgent.selectConnectionUrl(remoteDevice, UUID);

            System.out.println("\nConnecting to " + connectionUrl);

            // Connect Server
            try {
                primary.load(Primary.Type.SERVER, username, password);
            } catch (Exception e) { // If fail
                primary.load(Primary.Type.SECONDARY, username, password);
            }
            primary.connect(connectionUrl);
            primary.authenticate();
            primary.close();
        }
    }
}
