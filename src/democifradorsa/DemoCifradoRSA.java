/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package democifradorsa;

import java.io.File;
import java.util.Base64;

/**
 *
 * @author datasoft-edgardo
 */
public class DemoCifradoRSA {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            System.out.println("============TEST CON P12================");
            testConP12();
            System.out.println("============================");
            System.out.println("============================");
            System.out.println("============TEST CON ALMACEN WINDOWS================");
            testConAlmacenWindows();
        } catch (Exception e) {
        }
    }

    private static void testConP12() {
        try {
            //certificado en formato p12 o pfx (debe contener llave privada, publica y certificado)
            File fContenedorp12 = new File("myCertCreado.p12");
            //clave del p12 o pfx
            String Contenedorp12clave = "Passw0rd";
            String originalText = "demostracion de cifrado con llave publica.!!";
            EncryptionRSA encryptionUtil = new EncryptionRSA();
            CertificateEntity certificateEntity = encryptionUtil.getCertificateP12(fContenedorp12, Contenedorp12clave);
            //Encripta String con llave publica
            byte[] cipherText = encryptionUtil.encryptWithPubKey(originalText, certificateEntity);
            //Desencripta con llave privada
            String plainText = encryptionUtil.decryptWithPrivKey(cipherText, certificateEntity);

            //Se imprime string encriptado y desencriptado
            System.out.println("Original Text: " + originalText);
            System.out.println("Encrypted Text: " + Base64.getEncoder().encodeToString(cipherText));
            System.out.println("Decrypted Text: " + plainText);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
    private static void testConAlmacenWindows() {
        try {
            String originalText = "demostracion de cifrado con llave publica.!!";
            EncryptionRSA encryptionUtil = new EncryptionRSA();
            CertificateEntity certificateEntity = encryptionUtil.getStoreWindows("Edgardo Vasquez");
            //Encripta String con llave publica
            byte[] cipherText = encryptionUtil.encryptWithPubKey(originalText, certificateEntity);
            //Desencripta con llave privada
            String plainText = encryptionUtil.decryptWithPrivKey(cipherText, certificateEntity);

            //Se imprime string encriptado y desencriptado
            System.out.println("Original Text: " + originalText);
            System.out.println("Encrypted Text: " + Base64.getEncoder().encodeToString(cipherText));
            System.out.println("Decrypted Text: " + plainText);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
