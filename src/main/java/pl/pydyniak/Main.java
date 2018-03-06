package pl.pydyniak;

import iaik.pkcs.pkcs11.TokenException;
import pl.pydyniak.signature.GeneralSmartCardReader;
import pl.pydyniak.signature.SmartCardCertificate;
import pl.pydyniak.signature.SmartCardReader;
import pl.pydyniak.signature.Token;
import pl.pydyniak.xml.XadesXmlSigner;
import pl.pydyniak.xml.XmlSigner;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;

/**
 * Created by rafal on 2/17/18.
 */
public class Main {
    /**
     * Just a demo - exceptions are NOT handled and they SHOULD be.
     * Exception can occur at many places like giving wrong PIN or picking not existing slot
     * @param args
     * @throws Exception
     */
    public static void main(String... args) throws Exception {
        SmartCardCertificate certificate = getCertificate();
        XmlSigner xmlSigner = new XadesXmlSigner();
        File signedFile = new File("out/signed.sig");
        xmlSigner.sign(new File("test_xml_to_sign.xml"), signedFile, certificate.getPrivateKey(), certificate.getX509Certificate());
        System.out.println("Signed file saved in: " + signedFile.getAbsolutePath());
    }

    private static SmartCardCertificate getCertificate() throws TokenException, IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));


        SmartCardReader smartCardReader = new GeneralSmartCardReader("CCPkiP11.dll");
        List<Token> avaliableTokens = smartCardReader.getAvaliableTokens();
        avaliableTokens.forEach(System.out::println);
        System.out.println("Pick which token to use: ");
        String slotId = br.readLine();
        System.out.println("Enter pin:");
        String pin = br.readLine();
        List<SmartCardCertificate> certificates = smartCardReader.getCertificates(Integer.parseInt(slotId), pin.toCharArray());
        for (int i=0; i<certificates.size(); i++) {
            SmartCardCertificate certificate = certificates.get(i);
            System.out.println(i+": " + certificate.getAlias());
        }

        System.out.println("Pick certificate:");
        String pickedCertificate = br.readLine();

        return certificates.get(Integer.parseInt(pickedCertificate));
    }
}
