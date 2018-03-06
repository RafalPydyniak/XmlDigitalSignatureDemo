package pl.pydyniak.signature;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class SmartCardCertificate {
    private String alias;
    private X509Certificate x509Certificate;
    private PrivateKey privateKey;

    public SmartCardCertificate(String alias, X509Certificate x509Certificate, PrivateKey privateKey) {
        this.alias = alias;
        this.x509Certificate = x509Certificate;
        this.privateKey = privateKey;
    }

    public String getAlias() {
        return alias;
    }

    public X509Certificate getX509Certificate() {
        return x509Certificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public String toString() {
        return "SmartCardCertificate{" +
                "alias='" + alias + '\'' +
                ", x509Certificate=" + x509Certificate +
                ", privateKey=" + privateKey +
                '}';
    }
}
