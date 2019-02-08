package com.kweisa.primary.bluetooth;

import javax.bluetooth.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Scanner;

public class DiscoverAgent {
    private static final Scanner SCANNER = new Scanner(System.in);

    private static ArrayList<RemoteDevice> discoverDevices() throws BluetoothStateException, InterruptedException {
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

    private static ArrayList<String> discoverServices(RemoteDevice remoteDevice, UUID serviceUUID) throws InterruptedException, BluetoothStateException {
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

    public static RemoteDevice selectRemoteDevice() throws InterruptedException, BluetoothStateException {
        // Find server
        ArrayList<RemoteDevice> remoteDevices = DiscoverAgent.discoverDevices();
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
            return null;
        } else if (remoteDevices.size() == 1) {
            System.out.println("0");
            remoteDevice = remoteDevices.get(0);
        } else {
            remoteDevice = remoteDevices.get(SCANNER.nextInt());
        }

        return remoteDevice;
    }

    public static String selectConnectionUrl(RemoteDevice remoteDevice, UUID uuid) throws BluetoothStateException, InterruptedException {
        // Find service
        ArrayList<String> connectionUrls = DiscoverAgent.discoverServices(remoteDevice, uuid);

        for (int i = 0; i < connectionUrls.size(); i++) {
            System.out.printf("%d. %s\n", i, connectionUrls.get(i));
        }

        // Select service
        System.out.print("Select connection URL > ");

        String connectionUrl;
        if (connectionUrls.size() == 0) {
            System.out.println("NOT FOUND");
            return null;
        } else if (connectionUrls.size() == 1) {
            connectionUrl = connectionUrls.get(0);
        } else {
            connectionUrl = connectionUrls.get(SCANNER.nextInt());
        }

        return connectionUrl;
    }
}
