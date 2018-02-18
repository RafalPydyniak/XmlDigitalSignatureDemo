package pl.pydyniak.xml;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Created by rafal on 2/17/18.
 */
public class XmlSignerImpl implements XmlSigner {
    @Override
    public Document sign(Document xmlToSign, PublicKey publicKey, PrivateKey privateKey) throws XmlSigningException {
        try {
            return tryToSignOrThrow(xmlToSign, publicKey, privateKey);
        } catch (Exception e) {
            //TODO this is just a demo, in real life we want to do something better with exceptions
            e.printStackTrace();
            throw new XmlSigningException();
        }
    }

    private Document tryToSignOrThrow(Document xmlToSign, PublicKey publicKey, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyException, ParserConfigurationException, MarshalException, XMLSignatureException, TransformerException, FileNotFoundException {
        XMLSignature xmlSignature = prepareXmlSignature(publicKey, xmlToSign);
        Document doc = getEmptyDocument();
        DOMSignContext domSignContext = new DOMSignContext(privateKey, doc);
        xmlSignature.sign(domSignContext);

        String resultFile = "xmlOut.xml";
        saveDocumentToFile(doc, resultFile);
        return xmlToSign;
    }

    private XMLSignature prepareXmlSignature(PublicKey publicKey, Document xmlToSign) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyException {
        XMLSignatureFactory xmlSignFactory = XMLSignatureFactory.getInstance("DOM");
        List<XMLObject> objects = getObjectsFromData(xmlToSign, xmlSignFactory);
        SignedInfo signedInfo = getSignedInfo(xmlSignFactory);
        KeyInfo keyInfo = getKeyInfo(publicKey, xmlSignFactory);
        return xmlSignFactory.newXMLSignature(signedInfo, keyInfo, objects, "Signature", "SignatureValue");
    }

    private List<XMLObject> getObjectsFromData(Document xmlToSign, XMLSignatureFactory xmlSignFactory) {
        List<XMLObject> objects = new ArrayList<>();
        Node content = xmlToSign.getFirstChild();
        XMLObject data = xmlSignFactory.newXMLObject(Collections.singletonList(content), "Data", "text/xml", null);
        objects.add(data);
        return objects;
    }

    private SignedInfo getSignedInfo(XMLSignatureFactory xmlSignFactory) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        DigestMethod digestMethod = xmlSignFactory.newDigestMethod(DigestMethod.SHA1, null);
        Transform transform = xmlSignFactory.newTransform(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (TransformParameterSpec) null);
        Reference reference = xmlSignFactory.newReference("#Data", digestMethod, Collections.singletonList(transform), null, null);
        SignatureMethod signatureMethod = xmlSignFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null);
        CanonicalizationMethod canonicalizationMethod = xmlSignFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);

        return xmlSignFactory.newSignedInfo(canonicalizationMethod, signatureMethod, Collections.singletonList(reference));
    }

    private KeyInfo getKeyInfo(PublicKey publicKey, XMLSignatureFactory xmlSignFactory) throws KeyException {
        KeyInfoFactory keyInfoFactory = xmlSignFactory.getKeyInfoFactory();
        KeyValue keyValue = keyInfoFactory.newKeyValue(publicKey);
        return keyInfoFactory.newKeyInfo(Collections.singletonList(keyValue));
    }

    private Document getEmptyDocument() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().newDocument();
    }

    private void saveDocumentToFile(Document doc, String resultFile) throws TransformerException, FileNotFoundException {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.transform(
                new DOMSource(doc),
                new StreamResult(
                        new FileOutputStream(resultFile)));
    }
}
