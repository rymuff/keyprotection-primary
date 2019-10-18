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

        System.out.print("Username> primary-device\n");
        // String username = scanner.nextLine();
        String username = "primary-device";

        System.out.print("Password> password\n");
        // String password = scanner.nextLine();
        String password = "password";

        Primary primary = new Primary(UUID);

        if (choice == 1) {
            primary.enroll(username, password);
        } else if (choice == 2) {
            RemoteDevice remoteDevice = DiscoverAgent.selectRemoteDevice();
            String connectionUrl = DiscoverAgent.selectConnectionUrl(remoteDevice, UUID);
            for (int i = 0; i < 100; i++) {
//                Thread.sleep(500);
                primary.time = System.currentTimeMillis();
                System.out.println("\nConnecting to " + connectionUrl);

                // Connect Server
                primary.load(Primary.Type.SECONDARY, username, password);
//                try {
////                    primary.load(Primary.Type.SERVER, username, password);
////                    primary.load(Primary.Type.LOCAL, username, password);
//                } catch (Exception e) { // If SERVER fail
////                    primary.load(Primary.Type.SECONDARY, username, password);
//                }
                primary.connect(connectionUrl);
                primary.authenticate();
                primary.close();
                System.out.printf("Time: " + (System.currentTimeMillis() - primary.time - primary.time2));
            }
        }
    }
}
