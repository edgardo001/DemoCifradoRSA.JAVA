/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package democifradorsa;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author JavaDigest
 *
 */
public class EncryptionRSA {

    /**
     * String to hold name of the encryption algorithm.
     */
    public static final String ALGORITHM = "RSA";

    public EncryptionRSA() {
        //Se agrega bouncyCastle al provider de java, si no se realiza, arroja un error
        Provider p = new BouncyCastleProvider();
        Security.addProvider(p);
    }

    //static PrivateKey privkey;
    //static PublicKey pubkey;
    public CertificateEntity getCertificateP12(File certP12, String clave) {
        CertificateEntity myCert = null;
        try {
            //Se instancia un keystore de tipo pkcs12 para leer el contenedor p12 o pfx
            KeyStore ks = KeyStore.getInstance("pkcs12");
            //Se entrega la ruta y la clave del p12 o pfx
            ks.load(new FileInputStream(certP12.getAbsolutePath()), clave.toCharArray());

            //Se obtiene el nombre del certificado
            String alias = (String) ks.aliases().nextElement();

            // Get certificate of public keystore  
            //Certificate certificate = ks.getCertificateP12(alias);
            //Get public key
            //pubkey = certificate.getPublicKey();
            //Se obtiene la llave privada
            //privkey = (PrivateKey) ks.getKey(alias, Contenedorp12clave.toCharArray());
            myCert = new CertificateEntity();
            //Get public key
            myCert.setX509Certificate((X509Certificate) ks.getCertificate(alias));
            //Se obtiene la llave privada
            myCert.setPrivateKey((PrivateKey) ks.getKey(alias, clave.toCharArray()));

        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | CertificateException e) {
            System.out.println(e.getMessage());
        }
        return myCert;
    }

    public CertificateEntity getStoreWindows(String nombreCert) {
        CertificateEntity myCert = null;
        try {
            KeyStore ks = KeyStore.getInstance("Windows-MY");
            ks.load(null, null);
            Enumeration en = ks.aliases();

            while (en.hasMoreElements()) {
                String aliasKey = (String) en.nextElement();
                if (nombreCert.equals(aliasKey)) {
                    myCert = new CertificateEntity();
                    myCert.setX509Certificate((X509Certificate) ks.getCertificateChain(aliasKey)[0]);
                    myCert.setPrivateKey((PrivateKey) ks.getKey(aliasKey, null));
                    break;
                }
            }
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
            System.out.println(e.getMessage());
        }
        return myCert;
    }

    /**
     * Encrypt the plain text using public key.
     *
     * @param text : original plain text
     * @param myCertificate
     * @return Encrypted text
     */
    public byte[] encryptWithPubKey(String text, CertificateEntity myCertificate) {
        byte[] cipherText = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(ALGORITHM);
            // encryptWithPubKey the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, myCertificate.getX509Certificate().getPublicKey());
            cipherText = cipher.doFinal(text.getBytes());
        } catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    /**
     * Decrypt text using private key.
     *
     * @param text :encrypted text
     * @param myCertificate
     * @return plain text
     */
    public String decryptWithPrivKey(byte[] text, CertificateEntity myCertificate) {
        byte[] dectyptedText = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(ALGORITHM);

            // decryptWithPrivKey the text using the private key
            cipher.init(Cipher.DECRYPT_MODE, myCertificate.getPrivateKey());
            dectyptedText = cipher.doFinal(text);

        } catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException ex) {
            ex.printStackTrace();
        }
        return new String(dectyptedText);
    }

    /**
     * Encrypt the plain text using private key.
     *
     * @param text : original plain text
     * @param myCertificate
     * @return Encrypted text
     */
    public byte[] encryptWithPrivKey(String text, CertificateEntity myCertificate) {
        byte[] cipherText = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(ALGORITHM);
            // encryptWithPubKey the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, myCertificate.getX509Certificate().getPublicKey());
            cipherText = cipher.doFinal(text.getBytes());
        } catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    /**
     * Decrypt text using public key.
     *
     * @param text :encrypted text
     * @param myCertificate
     * @return plain text
     */
    public String decryptWithPubKey(byte[] text, CertificateEntity myCertificate) {
        byte[] dectyptedText = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(ALGORITHM);

            // decryptWithPrivKey the text using the private key
            cipher.init(Cipher.DECRYPT_MODE, myCertificate.getPrivateKey());
            dectyptedText = cipher.doFinal(text);

        } catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException ex) {
            ex.printStackTrace();
        }
        return new String(dectyptedText);
    }
}
