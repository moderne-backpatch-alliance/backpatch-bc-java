package org.bouncycastle.pkcs.test;

import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.ScryptParams;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

/**
 * The PBES2 key-derivation cost of an encrypted PKCS#8 key is bounded by default, before the
 * derivation runs. The encrypted content is never reached, so it is filler.
 */
public class PBEKDFCostTest
    extends TestCase
{
    private static final char[] PASSWORD = "hello".toCharArray();

    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testPbkdf2DefaultIterationBound()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo info = pbkdf2Key(10000001);

        checkRejected(info, new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(PASSWORD),
            "iteration count (10000001) greater than 10000000");
        checkRejected(info, new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(PASSWORD),
            "iteration count (10000001) greater than 10000000");
    }

    public void testScryptBlockSizeBound()
        throws Exception
    {
        checkRejected(scryptKey(2, 2048, 1), new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(PASSWORD),
            "scrypt block size (2048) greater than 1024");
    }

    public void testScryptCostBound()
        throws Exception
    {
        String old = System.getProperty("org.bouncycastle.pbe.max_scrypt_memory");
        System.setProperty("org.bouncycastle.pbe.max_scrypt_memory", String.valueOf(1 << 20));
        try
        {
            InputDecryptorProvider decProv = new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(PASSWORD);

            checkRejected(scryptKey(1 << 14, 1, 1), decProv, "scrypt cost parameters require more than 1048576 bytes");
            checkRejected(scryptKey(2, 1, 1 << 14), decProv, "scrypt cost parameters require more than 1048576 bytes");
        }
        finally
        {
            if (old == null)
            {
                System.clearProperty("org.bouncycastle.pbe.max_scrypt_memory");
            }
            else
            {
                System.setProperty("org.bouncycastle.pbe.max_scrypt_memory", old);
            }
        }
    }

    private static void checkRejected(PKCS8EncryptedPrivateKeyInfo info, InputDecryptorProvider decProv, String message)
    {
        try
        {
            info.decryptPrivateKeyInfo(decProv);
            fail("KDF cost accepted");
        }
        catch (Exception e)
        {
            assertTrue("unexpected exception: " + e, String.valueOf(e.getMessage()).indexOf(message) >= 0);
        }
    }

    private static PKCS8EncryptedPrivateKeyInfo pbkdf2Key(int iterationCount)
    {
        KeyDerivationFunc kdf = new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2,
            new PBKDF2Params(new byte[16], iterationCount, 32,
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE)));

        return encryptedKey(kdf);
    }

    private static PKCS8EncryptedPrivateKeyInfo scryptKey(int n, int r, int p)
    {
        KeyDerivationFunc kdf = new KeyDerivationFunc(MiscObjectIdentifiers.id_scrypt,
            new ScryptParams(new byte[16], n, r, p, 32));

        return encryptedKey(kdf);
    }

    private static PKCS8EncryptedPrivateKeyInfo encryptedKey(KeyDerivationFunc kdf)
    {
        EncryptionScheme scheme = new EncryptionScheme(NISTObjectIdentifiers.id_aes256_CBC, new DEROctetString(new byte[16]));
        AlgorithmIdentifier algId = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, new PBES2Parameters(kdf, scheme));

        return new PKCS8EncryptedPrivateKeyInfo(new EncryptedPrivateKeyInfo(algId, new byte[32]));
    }
}
