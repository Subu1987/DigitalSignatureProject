package com.example;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.*;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Enumeration;
import sun.security.pkcs11.SunPKCS11;

public class UsbTokenPdfSigner {

    // Global PIN/password for USB token access
    private static final String TOKEN_PIN = "abcd#1234";

    public static void main(String[] args) throws Exception {
        // Path to your PKCS#11 driver library (.dll or .so)
        String pkcs11Config = "name = Token\n" +
                "library = C:/Windows/System32/eps2003csp11v2.dll";

        // Create temp config file
        File configFile = File.createTempFile("pkcs11", ".cfg");
        try (FileWriter writer = new FileWriter(configFile)) {
            writer.write(pkcs11Config);
        }

        // Load the PKCS#11 provider
        Provider provider = new SunPKCS11(configFile.getAbsolutePath());
        Security.addProvider(provider);

        // Load the keystore from USB token
        KeyStore ks = KeyStore.getInstance("PKCS11", provider);
        ks.load(null, TOKEN_PIN.toCharArray()); // Token PIN

        String alias = getPrivateKeyAlias(ks);
        if (alias == null) {
            throw new RuntimeException("No private key alias found on the token.");
        }

        // Debug: Log the alias to ensure it's correct
        System.out.println("Private key alias: " + alias);

        // Retrieve private key and certificate chain
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, TOKEN_PIN.toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);

        // Debug: Log private key and certificate chain
        System.out.println("Private key loaded: " + (privateKey != null));
        System.out.println("Certificate chain loaded: " + (chain != null && chain.length > 0));

        if (privateKey == null || chain == null || chain.length == 0) {
            throw new RuntimeException("Failed to retrieve private key or certificate chain from token.");
        }

        // Paths
        String src = "pdfFiles/input.pdf"; // Unsigned PDF
        String dest = "pdfFiles/signed_output.pdf"; // Signed PDF

        // Sign the PDF
        signPdf(src, dest, privateKey, chain);

        System.out.println("PDF signed successfully!");

        configFile.delete(); // Clean up
    }

    // Method to iterate over aliases and get the one that has a private key
    private static String getPrivateKeyAlias(KeyStore keyStore) throws KeyStoreException {
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Found alias: " + alias);
            if (keyStore.isKeyEntry(alias)) {
                System.out.println("Alias contains private key: " + alias);
                return alias;
            }
        }
        return null;
    }

    // Method to sign the PDF
    public static void signPdf(String src, String dest, PrivateKey privateKey, Certificate[] chain)
            throws IOException, DocumentException, GeneralSecurityException {

        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');

        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason("Document Signing");
        appearance.setLocation("India");

        // Set the visible signature field and the position
        appearance.setVisibleSignature(new Rectangle(116.965f, 48.603f, 250f, 100f), 1, "Authorized Signatory");

        ExternalDigest digest = new BouncyCastleDigest();
        ExternalSignature signature = new PrivateKeySignature(privateKey, DigestAlgorithms.SHA256, "SunPKCS11-Token");

        // Debug: Check the parameters being passed to the signDetached method
        System.out.println("Signing the PDF with the following parameters:");
        System.out.println("Private key: " + privateKey);
        System.out.println("Certificate chain length: " + chain.length);

        MakeSignature.signDetached(
                appearance,
                digest,
                signature,
                chain,
                null,
                null,
                null,
                0,
                MakeSignature.CryptoStandard.CMS);
    }
}
