package pl.pydyniak.signature;

import iaik.pkcs.pkcs11.TokenException;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;

/**
 * Created by pydyra on 2/20/2018.
 */
public interface SmartCardReader {
    List<Token> getAvaliableTokens() throws TokenException;

    List<SmartCardCertificate> getCertificates(long slotId, char[] pin) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException;
}
