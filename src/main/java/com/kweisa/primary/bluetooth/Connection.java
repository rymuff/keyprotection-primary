package com.kweisa.primary.bluetooth;

import javax.microedition.io.Connector;
import javax.microedition.io.StreamConnection;
import java.io.*;
import java.util.Base64;

public class Connection {
    StreamConnection streamConnection;
    BufferedReader bufferedReader;
    BufferedWriter bufferedWriter;

    private String connectionUrl;

    Connection() {
    }

    public Connection(String connectionUrl) {
        this.connectionUrl = connectionUrl;
    }

    public void open() throws IOException {
        streamConnection = (StreamConnection) Connector.open(connectionUrl);
        bufferedReader = new BufferedReader(new InputStreamReader(streamConnection.openInputStream()));
        bufferedWriter = new BufferedWriter(new OutputStreamWriter(streamConnection.openOutputStream()));
    }

    public void send(String message) throws IOException {
        bufferedWriter.write(message + "\n");
        bufferedWriter.flush();

        System.out.printf("[>] %s\n", message);
    }

    public void send(byte[] data) throws IOException {
        String message = Base64.getEncoder().encodeToString(data);

        bufferedWriter.write(message + "\n");
        bufferedWriter.flush();

        System.out.printf("[>] %s\n", message);
    }

    public byte[] receiveEncoded() throws IOException {
        String message = bufferedReader.readLine();
        System.out.printf("[<] %s\n", message);

        return Base64.getDecoder().decode(message);
    }

    public int receiveInt() throws IOException {
        int data = bufferedReader.read();
        System.out.printf("[<] INT:%d\n", data);

        return data;
    }

    public String receiveString() throws IOException {
        String message = bufferedReader.readLine();
        System.out.printf("[<] %s\n", message);

        return message;
    }


    public void close() throws IOException {
        bufferedReader.close();
        bufferedWriter.close();
        streamConnection.close();
    }
}
