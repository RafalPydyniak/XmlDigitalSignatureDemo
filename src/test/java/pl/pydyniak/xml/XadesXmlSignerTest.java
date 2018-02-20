package pl.pydyniak.xml;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.X509Certificate;

/**
 * Created by pydyra on 2/19/2018.
 */
public class XadesXmlSignerTest {
    @Test
    public void shouldGenerateProperXadesSign() throws Exception{
        XadesXmlSigner xmlSigner = new XadesXmlSigner();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        String xmlString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<example>\n" +
                "    <message>Hello World!</message>\n" +
                "</example>";
        System.out.println(xmlString);
        InputSource inputSource = new InputSource(new StringReader(xmlString));
        Document document = documentBuilder.parse(inputSource);
        X509Certificate certificate = Mockito.mock(X509Certificate.class);
        Principal principalMock = Mockito.mock(Principal.class);
        Mockito.when(principalMock.getName()).thenReturn("Mocked issuerDN");
        Mockito.when(certificate.getIssuerDN()).thenReturn(principalMock);
        Mockito.when(certificate.getSerialNumber()).thenReturn(new BigInteger("123456"));
        File signedFile = xmlSigner.sign(document, keyPair.getPublic(), keyPair.getPrivate(), new File("build/xmlOut.xml"), certificate);

        Assert.assertTrue(signedFile.exists());
        Document signedFileDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(signedFile);
        Assert.assertEquals("Signature", signedFileDocument.getFirstChild().getNodeName());
        Assert.assertEquals(2, signedFileDocument.getElementsByTagName("Object").getLength());
    }
}