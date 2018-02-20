package pl.pydyniak.xml;

import org.w3c.dom.Document;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.File;
import java.io.FileNotFoundException;
import java.security.*;
import java.security.cert.X509Certificate;

/**
 * Created by rafal on 2/17/18.
 */
public interface XmlSigner {
    File sign(Document xmlToSign, PublicKey publicKey, PrivateKey privateKey, File destinationFile, X509Certificate cert) throws XmlSigningException;
}
