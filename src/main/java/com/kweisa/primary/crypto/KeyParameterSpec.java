package com.kweisa.primary.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class KeyParameterSpec{
    private byte[] salt;
    private byte[] nonce;
    private byte[] encryptedPrivateKey;

    public KeyParameterSpec(String password, byte[] privateKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        salt = Crypto.generateRandomBytes(64);
        nonce = Crypto.generateRandomBytes(32);
        SecretKey secretKey = Crypto.deriveKey(password, salt);
        encryptedPrivateKey = Crypto.encrypt(secretKey, nonce, privateKeyBytes);
    }

    public byte[] getSalt() {
        return salt;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public byte[] getEncryptedPrivateKey() {
        return encryptedPrivateKey;
    }
}