package com.kweisa.primary.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class Util {
    public static byte[] readBytesFromFile(File file) throws IOException {
        FileInputStream fileInputStream = new FileInputStream(file);
        byte[] bytes = new byte[fileInputStream.available()];
        if (fileInputStream.available() != fileInputStream.read(bytes)) {
            fileInputStream.close();
            throw new IOException();
        }
        fileInputStream.close();

        return bytes;
    }

    public static void writeBytesToFile(File file, byte[] data) throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        fileOutputStream.write(data);
        fileOutputStream.close();
    }
}
