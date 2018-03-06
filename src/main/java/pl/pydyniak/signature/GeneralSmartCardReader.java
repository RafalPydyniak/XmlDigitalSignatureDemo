package pl.pydyniak.signature;


import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.provider.Constants;
import iaik.pkcs.pkcs11.provider.DefaultLoginManager;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.security.provider.IAIK;
import iaik.xml.crypto.XSecProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Created by pydyra on 2/20/2018.
 */
public class GeneralSmartCardReader implements SmartCardReader {
    private static final Logger logger = LogManager.getLogger(GeneralSmartCardReader.class);
    private final String driver;

    public GeneralSmartCardReader(String driver) {
        this.driver = driver;
    }

    /**
     * Method that returns avaliable tokens for driver passed in parameter
     *
     * @return
     * @throws TokenException - exception can be thrown in IAIKPkcs11.getModule method. Exception handling is beyond scope of this demo app
     */
    @Override
    public List<Token> getAvaliableTokens() throws TokenException {
        Properties properties = new Properties();
        properties.put("PKCS11_NATIVE_MODULE", driver);
        Module module = IAIKPkcs11.getModule(properties);
        Slot[] slotList = module.getSlotList(true);
        List<Token> tokens = Arrays.stream(slotList).map(slot -> {
            try {
                return new Token(slot.getSlotID(), slot.getToken().getTokenInfo().getLabel());
            } catch (TokenException e) {
                return null;
            }
        }).filter(Objects::nonNull).collect(Collectors.toList());
        return tokens;
    }

    /**
     * Gets certificates avaliable on given slot.
     *
     * @param slotId
     * @param pin
     * @return
     * @throws CertificateException     Exception handling is beyond scope of this demo app
     * @throws NoSuchAlgorithmException Exception handling is beyond scope of this demo app
     * @throws IOException              Exception handling is beyond scope of this demo app
     */
    @Override
    public List<SmartCardCertificate> getCertificates(long slotId, char[] pin) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        Security.insertProviderAt(new IAIK(), 2);
        Security.insertProviderAt(new XSecProvider(), 3);
        KeyStore keyStore = getPKCS11KeyStore(driver, pin, slotId);
        return getCertificatesFromKeystore(keyStore);
    }

    private KeyStore getPKCS11KeyStore(String driver, char[] pin, long slotId) throws CertificateException, NoSuchAlgorithmException, IOException {
        Properties properties = getProperties(driver, pin, slotId);
        IAIKPkcs11 provider = new IAIKPkcs11(properties);
        Security.insertProviderAt(provider, 2);
        Properties loginProperties = new Properties();
        DefaultLoginManager loginManager = new DefaultLoginManager(loginProperties);
        provider.setLoginManager(loginManager);
        provider.getTokenManager().getKeyStore();
        KeyStore keyStore = provider.getTokenManager().getKeyStore();
        keyStore.load(null, pin);
        return keyStore;
    }

    private Properties getProperties(String driver, char[] pin, long slotID) {
        Properties properties = new Properties();
        properties.setProperty(Constants.KEY_STORE_SUPPORT_PROVIDER, "IAIK");
        properties.setProperty(Constants.SESSION_POOL_MAX_SIZE, "100");
        properties.setProperty(Constants.MULTI_THREAD_INIT, "true");
        properties.setProperty(Constants.LOGIN_KEYSTORE_SESSION_ON_DEMAND, "false");
        properties.setProperty(Constants.PKCS11_NATIVE_MODULE, driver);
        properties.setProperty(Constants.CHECK_MECHANISM_SUPPORTED, "true");
        properties.setProperty(Constants.USER_PIN, String.valueOf(pin));
        properties.setProperty(Constants.SLOT_ID, String.valueOf(slotID));
        return properties;
    }

    /**
     * Returns certificates on keystore.
     * Keep in mind that this method is just a sample method so not all exceptions are handled properly!
     * @param keyStore
     * @return
     * @throws KeyStoreException
     */
    private List<SmartCardCertificate> getCertificatesFromKeystore(KeyStore keyStore) throws KeyStoreException {
        return Collections.list(keyStore.aliases()).stream().map(alias -> {
            try {
                Key key = keyStore.getKey(alias, null);
                if (key instanceof RSAPrivateKey) {
                    Certificate[] certificateChain = keyStore.getCertificateChain(alias);

                    X509Certificate signerCertificate = (X509Certificate) certificateChain[0];
                    boolean[] keyUsage = signerCertificate.getKeyUsage();
                    if ((keyUsage == null) || keyUsage[0] || keyUsage[1]) {
                        return new SmartCardCertificate(alias, signerCertificate, (PrivateKey) key);
                    }
                }
                return null;
            } catch (Exception e) {
                throw new RuntimeException();
            }
        }).filter(Objects::nonNull).collect(Collectors.toList());
    }
}
