package org.bouncycastle.tls.test;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import junit.framework.TestCase;

import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JceDefaultTlsCredentialedDecryptor;
import org.bouncycastle.util.Arrays;

/**
 * RSA key exchange: the server's EncryptedPreMasterSecret decryption (CVE-2024-30171, "Marvin").
 * <p>
 * The structural check (testJceBadPaddingRaisesNoProviderException) is that a ciphertext with bad
 * PKCS#1 padding no longer makes the BC provider's Cipher throw a BadPaddingException that the
 * decryptor then catches, the exception-handling timing signal the advisory names. No test here
 * measures time: none of them shows that the decryption is constant-time.
 */
public class RSAPreMasterSecretDecryptionTest
    extends TestCase
{
    private static final String CERT = "x509-server-rsa-enc.pem";
    private static final String KEY = "x509-server-key-rsa-enc.pem";

    private final SecureRandom random = new SecureRandom();
    private final Provider bc = new BouncyCastleProvider();

    private RSAPrivateCrtKeyParameters bcKey;
    private RSAKeyParameters publicKey;

    protected void setUp()
        throws Exception
    {
        bcKey = (RSAPrivateCrtKeyParameters)TlsTestUtils.loadBcPrivateKeyResource(KEY);
        publicKey = new RSAKeyParameters(false, bcKey.getModulus(), bcKey.getPublicExponent());
    }

    public void testJceBadPaddingRaisesNoProviderException()
        throws Exception
    {
        RecordingSpi spi = new RecordingSpi();
        TlsCredentialedDecryptor decryptor = jceDecryptor(spi, bc);

        byte[] secret = decryptor.decrypt(params(ProtocolVersion.TLSv12), badPadding(preMasterSecret(ProtocolVersion.TLSv12)))
            .extract();

        assertEquals(48, secret.length);
        assertEquals("BadPaddingException raised by the provider's Cipher", 0, spi.badPadding);
    }

    public void testJceValidPreMasterSecret()
        throws Exception
    {
        byte[] pms = preMasterSecret(ProtocolVersion.TLSv12);
        TlsCredentialedDecryptor decryptor = jceDecryptor(new RecordingSpi(), bc);

        assertTrue(Arrays.areEqual(pms, decryptor.decrypt(params(ProtocolVersion.TLSv12), encrypt(pms)).extract()));
    }

    public void testJceVersionMismatchGivesAnotherSecret()
        throws Exception
    {
        byte[] pms = preMasterSecret(ProtocolVersion.TLSv10);
        TlsCredentialedDecryptor decryptor = jceDecryptor(new RecordingSpi(), bc);

        byte[] secret = decryptor.decrypt(params(ProtocolVersion.TLSv12), encrypt(pms)).extract();
        assertEquals(48, secret.length);
        assertFalse(Arrays.areEqual(pms, secret));
    }

    public void testJceOtherProviderUsesItsCipher()
        throws Exception
    {
        byte[] pms = preMasterSecret(ProtocolVersion.TLSv12);
        RecordingSpi spi = new RecordingSpi();
        TlsCredentialedDecryptor decryptor = jceDecryptor(spi, new Provider("Other", 1.0, "not BC")
        {
        });

        assertTrue(Arrays.areEqual(pms, decryptor.decrypt(params(ProtocolVersion.TLSv12), encrypt(pms)).extract()));
        assertEquals(1, spi.doFinal);
    }

    public void testBcValidPreMasterSecret()
        throws Exception
    {
        byte[] pms = preMasterSecret(ProtocolVersion.TLSv12);

        assertTrue(Arrays.areEqual(pms, bcDecryptor().decrypt(params(ProtocolVersion.TLSv12), encrypt(pms)).extract()));
    }

    public void testBcBadPaddingGivesAnotherSecret()
        throws Exception
    {
        byte[] pms = preMasterSecret(ProtocolVersion.TLSv12);

        byte[] secret = bcDecryptor().decrypt(params(ProtocolVersion.TLSv12), badPadding(pms)).extract();
        assertEquals(48, secret.length);
        assertFalse(Arrays.areEqual(pms, secret));
    }

    public void testBcVersionMismatchGivesAnotherSecret()
        throws Exception
    {
        byte[] pms = preMasterSecret(ProtocolVersion.TLSv10);

        byte[] secret = bcDecryptor().decrypt(params(ProtocolVersion.TLSv12), encrypt(pms)).extract();
        assertEquals(48, secret.length);
        assertFalse(Arrays.areEqual(pms, secret));
    }

    private TlsCredentialedDecryptor bcDecryptor()
        throws Exception
    {
        BcTlsCrypto crypto = new BcTlsCrypto(random);
        return new BcDefaultTlsCredentialedDecryptor(crypto, certificate(crypto.createCertificate(cert())), bcKey);
    }

    private TlsCredentialedDecryptor jceDecryptor(final RecordingSpi spi, final Provider cipherProvider)
        throws Exception
    {
        ProviderJcaJceHelper helper = new ProviderJcaJceHelper(bc)
        {
            public Cipher createCipher(String algorithm)
                throws NoSuchAlgorithmException, NoSuchPaddingException
            {
                if (algorithm.startsWith("RSA/"))
                {
                    spi.delegate = super.createCipher(algorithm);
                    return new RecordingCipher(spi, cipherProvider, algorithm);
                }
                return super.createCipher(algorithm);
            }
        };
        JcaTlsCrypto crypto = new JcaTlsCrypto(helper, random, random)
        {
        };
        PrivateKey privateKey = TlsTestUtils.loadJcaPrivateKeyResource(crypto, KEY);
        return new JceDefaultTlsCredentialedDecryptor(crypto, certificate(crypto.createCertificate(cert())), privateKey);
    }

    private static byte[] cert()
        throws Exception
    {
        return TlsTestUtils.loadBcCertificateResource(CERT).getEncoded();
    }

    private static Certificate certificate(TlsCertificate cert)
    {
        return new Certificate(new TlsCertificate[]{ cert });
    }

    private static TlsCryptoParameters params(final ProtocolVersion clientVersion)
    {
        return new TlsCryptoParameters(null)
        {
            public ProtocolVersion getRSAPreMasterSecretVersion()
            {
                return clientVersion;
            }
        };
    }

    private byte[] preMasterSecret(ProtocolVersion version)
    {
        byte[] pms = new byte[48];
        random.nextBytes(pms);
        pms[0] = (byte)version.getMajorVersion();
        pms[1] = (byte)version.getMinorVersion();
        return pms;
    }

    private byte[] encrypt(byte[] pms)
        throws Exception
    {
        PKCS1Encoding encoding = new PKCS1Encoding(new RSAEngine());
        encoding.init(true, publicKey);
        return encoding.processBlock(pms, 0, pms.length);
    }

    /**
     * The pre-master secret in a block type 1 (signature) frame instead of type 2: a well-formed
     * ciphertext whose decryption fails the PKCS#1 encryption padding check.
     */
    private byte[] badPadding(byte[] pms)
        throws Exception
    {
        int k = (publicKey.getModulus().bitLength() + 7) / 8;
        byte[] block = new byte[k];
        block[1] = 0x01;
        for (int i = 2; i < k - pms.length - 1; ++i)
        {
            block[i] = (byte)0xFF;
        }
        System.arraycopy(pms, 0, block, k - pms.length, pms.length);
        RSAEngine rsa = new RSAEngine();
        rsa.init(true, publicKey);
        return rsa.processBlock(block, 0, block.length);
    }

    private static class RecordingCipher
        extends Cipher
    {
        RecordingCipher(CipherSpi spi, Provider provider, String transformation)
        {
            super(spi, provider, transformation);
        }
    }

    /**
     * Delegates to the BC provider's own RSA Cipher and counts doFinal calls and BadPaddingExceptions.
     */
    private static class RecordingSpi
        extends CipherSpi
    {
        Cipher delegate;
        int doFinal = 0;
        int badPadding = 0;

        protected void engineSetMode(String mode)
        {
        }

        protected void engineSetPadding(String padding)
        {
        }

        protected int engineGetBlockSize()
        {
            return delegate.getBlockSize();
        }

        protected int engineGetOutputSize(int inputLen)
        {
            return delegate.getOutputSize(inputLen);
        }

        protected byte[] engineGetIV()
        {
            return delegate.getIV();
        }

        protected AlgorithmParameters engineGetParameters()
        {
            return delegate.getParameters();
        }

        protected void engineInit(int opmode, Key key, SecureRandom random)
            throws InvalidKeyException
        {
            delegate.init(opmode, key, random);
        }

        protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
        {
            delegate.init(opmode, key, params, random);
        }

        protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
        {
            delegate.init(opmode, key, params, random);
        }

        protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
        {
            return delegate.update(input, inputOffset, inputLen);
        }

        protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException
        {
            return delegate.update(input, inputOffset, inputLen, output, outputOffset);
        }

        protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException
        {
            ++doFinal;
            try
            {
                return delegate.doFinal(input, inputOffset, inputLen);
            }
            catch (BadPaddingException e)
            {
                ++badPadding;
                throw e;
            }
        }

        protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
        {
            ++doFinal;
            try
            {
                return delegate.doFinal(input, inputOffset, inputLen, output, outputOffset);
            }
            catch (BadPaddingException e)
            {
                ++badPadding;
                throw e;
            }
        }
    }
}
