package pl.pydyniak.xml;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
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
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Created by rafal on 2/17/18.
 */
public class XadesXmlSigner implements XmlSigner {
    @Override
    public File sign(Document xmlToSign, PublicKey publicKey, PrivateKey privateKey, File destinationFile, X509Certificate certificate) throws XmlSigningException {
        try {
            return tryToSignOrThrow(xmlToSign, publicKey, privateKey, destinationFile, certificate);
        } catch (Exception e) {
            //TODO this is just a demo, in real life we want to do something better with exceptions
            e.printStackTrace();
            throw new XmlSigningException();
        }
    }

    private File tryToSignOrThrow(Document xmlToSign, PublicKey publicKey, PrivateKey privateKey, File resultFile, X509Certificate certificate) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyException, ParserConfigurationException, MarshalException, XMLSignatureException, TransformerException, FileNotFoundException {
        XMLSignature xmlSignature = prepareXmlSignature(publicKey, xmlToSign, certificate);
        Document doc = getEmptyDocument();
        DOMSignContext domSignContext = new DOMSignContext(privateKey, doc);
        xmlSignature.sign(domSignContext);

        saveDocumentToFile(doc, resultFile);
        return resultFile;
    }

    private XMLSignature prepareXmlSignature(PublicKey publicKey, Document xmlToSign, X509Certificate certificate) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyException, ParserConfigurationException {
        XMLSignatureFactory xmlSignFactory = XMLSignatureFactory.getInstance("DOM");
        List<XMLObject> objects = getObjectsFromData(xmlToSign, xmlSignFactory, certificate);
        SignedInfo signedInfo = getSignedInfo(xmlSignFactory);
        KeyInfo keyInfo = getKeyInfo(publicKey, xmlSignFactory);
        return xmlSignFactory.newXMLSignature(signedInfo, keyInfo, objects, "Signature", "SignatureValue");
    }

    private Element createXadesObject(X509Certificate certificate) throws ParserConfigurationException {
        Document doc = getEmptyDocument();
        Element qualifyingProperties = createQualifyingPropertiesObject(doc);
        Element signedProperties = prepareSignedPropertiesElement(doc, certificate);
        qualifyingProperties.appendChild(signedProperties);
        return qualifyingProperties;
    }

    /**
     * Prepares SignedProperties element of XAdES
     * @param doc
     * @param certificate
     * @return
     */
    private Element prepareSignedPropertiesElement(Document doc, X509Certificate certificate) {
        Element signedProperties = createElementInDocument(doc, "xades:SignedProperties","SignedProperties" );

        Element signedSignatureProperties = prepareSignedSignatureProperties(doc, certificate);
        Element signedDataObjectProperties = prepareSignedDataObjectProperties(doc);

        signedProperties.appendChild(signedSignatureProperties);
        signedProperties.appendChild(signedDataObjectProperties);
        return signedProperties;
    }

    private Element prepareSignedDataObjectProperties(Document doc) {
        Element elSignedDataObjectProperties = doc.createElement("xades:SignedDataObjectProperties");
        elSignedDataObjectProperties.setAttribute("Id", "SignedDataObjectProperties");
        Element elDataObjectFormat = doc.createElement("xades:DataObjectFormat");
        elDataObjectFormat.setAttribute("ObjectReference", "#Data-Reference");
        Element elMimeType = doc.createElement("xades:MimeType");
        elMimeType.appendChild(doc.createTextNode("text/xml"));
        elDataObjectFormat.appendChild(elMimeType);
        elSignedDataObjectProperties.appendChild(elDataObjectFormat);

        Element commitmentTypeIndicationElement = doc.createElement("xades:CommitmentTypeIndication");
        elSignedDataObjectProperties.appendChild(commitmentTypeIndicationElement);
        Element elCommitmentTypeId = doc.createElement("xades:CommitmentTypeId");
        commitmentTypeIndicationElement.appendChild(elCommitmentTypeId);
        Element elIdentifier = doc.createElement("xades:Identifier");
        elIdentifier.appendChild(doc.createTextNode("http://uri.etsi.org/01903/v1.2.2#ProofOfApproval"));
        elCommitmentTypeId.appendChild(elIdentifier);
        Element elAllSignedDataObjects = doc.createElement("xades:AllSignedDataObjects");
        commitmentTypeIndicationElement.appendChild(elAllSignedDataObjects);
        return elSignedDataObjectProperties;
    }

    private Element prepareSignedSignatureProperties(Document doc, X509Certificate certificate) {
        Element signedSignatureProperties = createElementInDocument(doc, "xades:SignedSignatureProperties", "SignedSignatureProperties");
        Element signingTime = prepareSigningTimeElement(doc);
        Element signingCertificate = prepareSigningCertificateElement(doc, certificate);
        signedSignatureProperties.appendChild(signingTime);
        signedSignatureProperties.appendChild(signingCertificate);
        return signedSignatureProperties;
    }

    private Element prepareSigningCertificateElement(Document doc, X509Certificate certificate) {
        Element elSigningCertificate = doc.createElement("xades:SigningCertificate");
        Element elCertificate = doc.createElement("xades:Cert");
        Element elCertDigest = doc.createElement("xades:CertDigest");
        elCertificate.appendChild(elCertDigest);

        Element elIssuerSerial = doc.createElement("xades:IssuerSerial");
        elCertificate.appendChild(elIssuerSerial);
        Element elX509IssuerName = doc.createElement("X509IssuerName");
        elIssuerSerial.appendChild(elX509IssuerName);
        elX509IssuerName.appendChild(doc.createTextNode(certificate.getIssuerDN().getName()));
        Element elX509SerialNumber = doc.createElement("X509SerialNumber");
        elIssuerSerial.appendChild(elX509SerialNumber);
        elX509SerialNumber.appendChild(doc.createTextNode(certificate.getSerialNumber().toString()));

        elSigningCertificate.appendChild(elCertificate);
        return elSigningCertificate;
    }

    private Element prepareSigningTimeElement(Document doc) {
        Element elTime = doc.createElement("xades:SigningTime");
        elTime.appendChild(doc.createTextNode(new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss").format(new Date())));
        return elTime;
    }

    private Element createElementInDocument(Document document, String elementName, String elementId) {
        Element element = document.createElement(elementName);
        element.setAttribute("id", elementId);
        return element;
    }

    /**
     * Creates QualifyingProperties element
     * @param doc
     * @return
     */
    private Element createQualifyingPropertiesObject(Document doc) {
        Element qualifyingProperties = createElementInDocument(doc, "xades:QualifyingProperties", "QualifyingProperties");
        qualifyingProperties.setAttribute("Target", "#Signature");
        qualifyingProperties.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xades", "http://uri.etsi.org/01903/v1.3.2#");
        return qualifyingProperties;
    }

    private List<XMLObject> getObjectsFromData(Document xmlToSign, XMLSignatureFactory xmlSignFactory, X509Certificate certificate) throws ParserConfigurationException {
        List<XMLObject> objects = new ArrayList<>();
        XMLObject dataXmlObject = prepareDataXmlObject(xmlToSign, xmlSignFactory);
        XMLObject xadesXmlObject = prepareXadesXmlObject(xmlSignFactory, certificate);
        objects.add(dataXmlObject);
        objects.add(xadesXmlObject);

        return objects;
    }

    private XMLObject prepareXadesXmlObject(XMLSignatureFactory xmlSignFactory, X509Certificate certificate) throws ParserConfigurationException {
        Element qualifyingPropertiesElement = createXadesObject(certificate);
        return xmlSignFactory.newXMLObject(Collections.singletonList(new DOMStructure(qualifyingPropertiesElement)), null, null, null);
    }

    private XMLObject prepareDataXmlObject(Document xmlToSign, XMLSignatureFactory xmlSignFactory) {
        XMLStructure content = new DOMStructure(xmlToSign.getFirstChild());
        return xmlSignFactory.newXMLObject(Collections.singletonList(content), "Data", "text/xml", null);
    }

    private SignedInfo getSignedInfo(XMLSignatureFactory xmlSignFactory) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        DigestMethod digestMethod = xmlSignFactory.newDigestMethod(DigestMethod.SHA1, null);
        Transform transform = xmlSignFactory.newTransform(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (TransformParameterSpec) null);
        Reference dataReference = xmlSignFactory.newReference("#Data", digestMethod, Collections.singletonList(transform), null, "Data-Reference");
//        Reference signedPropertiesReference
//                = xmlSignFactory.newReference("#SignedProperties", digestMethod, Collections.singletonList(transform), "http://uri.etsi.org/01903#SignedProperties", "SignedProperties-Reference");
        SignatureMethod signatureMethod = xmlSignFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null);
        CanonicalizationMethod canonicalizationMethod = xmlSignFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);

        return xmlSignFactory.newSignedInfo(canonicalizationMethod, signatureMethod, Arrays.asList(dataReference));
//        return xmlSignFactory.newSignedInfo(canonicalizationMethod, signatureMethod, Arrays.asList(dataReference, signedPropertiesReference));
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

    private File saveDocumentToFile(Document doc, File resultFile) throws TransformerException, FileNotFoundException {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.transform(
                new DOMSource(doc),
                new StreamResult(
                        new FileOutputStream(resultFile)));
        return resultFile;
    }
}