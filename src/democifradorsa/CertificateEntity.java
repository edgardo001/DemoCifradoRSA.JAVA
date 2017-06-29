package democifradorsa;


import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author datasoft-edgardo
 */
    public class CertificateEntity {

        private X509Certificate x509Certificate;
        private PrivateKey privateKey;

        public CertificateEntity() {
        }
        public CertificateEntity(X509Certificate x509Certificate) {
            this.x509Certificate = x509Certificate;
        }
        public CertificateEntity(X509Certificate x509Certificate, PrivateKey privateKey) {
            this.x509Certificate = x509Certificate;
            this.privateKey = privateKey;
        }
        public X509Certificate getX509Certificate() {
            return x509Certificate;
        }
        public void setX509Certificate(X509Certificate x509Certificate) {
            this.x509Certificate = x509Certificate;
        }
        public PrivateKey getPrivateKey() {
            return privateKey;
        }
        public void setPrivateKey(PrivateKey privateKey) {
            this.privateKey = privateKey;
        }      
    }