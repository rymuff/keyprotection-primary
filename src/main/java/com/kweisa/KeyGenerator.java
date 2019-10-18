package com.kweisa;

import com.kweisa.primary.crypto.KeyParameterSpec;
import com.kweisa.primary.util.Util;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.util.Date;

public class KeyGenerator {
    public static void main(String[] args) throws Exception {
        // String[] algorithm = {"EC", "SHA256withECDSA"};
        String[] algorithm = {"RSA", "SHA256withRSA"};

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm[0]);
        keyPairGenerator.initialize(571);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        X509V1CertificateGenerator x509V1CertificateGenerator = new X509V1CertificateGenerator();

        x509V1CertificateGenerator.setSerialNumber(BigInteger.ONE);
        x509V1CertificateGenerator.setIssuerDN(new X500Principal("CN=kweisa.com"));
        x509V1CertificateGenerator.setNotBefore(new Date(System.currentTimeMillis()));
        x509V1CertificateGenerator.setNotAfter(new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000));
        x509V1CertificateGenerator.setSubjectDN(new X500Principal("CN=kweisa.com"));
        x509V1CertificateGenerator.setPublicKey(keyPair.getPublic());
        x509V1CertificateGenerator.setSignatureAlgorithm(algorithm[1]);
        Certificate certificate = x509V1CertificateGenerator.generate(keyPair.getPrivate());

        KeyParameterSpec keyParameterSpec = new KeyParameterSpec("password", keyPair.getPrivate().getEncoded());

        Util.writeBytesToFile(new File("primary.cert"), certificate.getEncoded());
        Util.writeBytesToFile(new File("local.key"), keyParameterSpec.getEncryptedPrivateKey());
        Util.writeBytesToFile(new File("local.salt"), keyParameterSpec.getSalt());
        Util.writeBytesToFile(new File("local.nonce"), keyParameterSpec.getNonce());
    }
}
