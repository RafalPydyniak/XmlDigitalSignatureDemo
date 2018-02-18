package pl.pydyniak.xml;

import org.w3c.dom.Document;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.FileNotFoundException;
import java.security.*;

/**
 * Created by rafal on 2/17/18.
 */
public interface XmlSigner {
    Document sign(Document xmlToSign, PublicKey publicKey, PrivateKey privateKey) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyException, MarshalException, XMLSignatureException, TransformerException, FileNotFoundException, ParserConfigurationException, XmlSigningException;
}
