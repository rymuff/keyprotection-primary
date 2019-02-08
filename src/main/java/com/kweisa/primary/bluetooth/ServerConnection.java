package com.kweisa.primary.bluetooth;

import javax.bluetooth.UUID;
import javax.microedition.io.Connector;
import javax.microedition.io.StreamConnectionNotifier;
import java.io.*;

public class ServerConnection extends Connection {
    private StreamConnectionNotifier streamConnectionNotifier;

    public ServerConnection(UUID uuid) throws IOException {
        String serverUrl = "btspp://localhost:" + uuid.toString() + ";name=PrimaryDevice";
        streamConnectionNotifier = (StreamConnectionNotifier) Connector.open(serverUrl);
    }

    public void accept() throws IOException {
        streamConnection = streamConnectionNotifier.acceptAndOpen();
        bufferedReader = new BufferedReader(new InputStreamReader(streamConnection.openInputStream()));
        bufferedWriter = new BufferedWriter(new OutputStreamWriter(streamConnection.openOutputStream()));
    }

    @Override
    public void close() throws IOException {
        super.close();
        streamConnectionNotifier.close();
    }
}
