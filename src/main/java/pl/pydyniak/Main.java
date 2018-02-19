package pl.pydyniak;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import pl.pydyniak.xml.XmlSignerImpl;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Created by rafal on 2/17/18.
 */
public class Main {
    public static void main(String... args) throws Exception {
        XmlSignerImpl xmlSigner = new XmlSignerImpl();
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
        xmlSigner.sign(document, keyPair.getPublic(), keyPair.getPrivate());
    }
}
