package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.IESParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

import java.math.BigInteger;

/**
 * support class for constructing intergrated encryption ciphers
 * for doing basic message exchanges on top of key agreement ciphers
 */
public class IESEngine
{
    BasicAgreement      agree;
    DerivationFunction  kdf;
    Mac                 mac;
    BufferedBlockCipher cipher;
    byte[]              macBuf;

    boolean             forEncryption;
    CipherParameters    privParam, pubParam;
    IESParameters       param;

    /**
     * set up for use with stream mode, where the key derivation function
     * is used to provide a stream of bytes to xor with the message.
     * <p>
     * <b>Security note:</b> this engine is initialised with static keys on both sides (the
     * {@link #init(boolean, CipherParameters, CipherParameters, CipherParameters)} entry point, which
     * supplies no ephemeral component), so the key-derivation input is the same for every message, and the
     * stream-mode keystream is identical from message to message - encrypting more than one message
     * under a given key pair is a many-time pad and leaks plaintext relationships. The static-static mode
     * is effectively deterministic encryption.
     * </p>
     *
     * @param agree the key agreement used as the basis for the encryption
     * @param kdf the key derivation function used for byte generation
     * @param mac the message authentication code generator for the message
     */
    public IESEngine(
        BasicAgreement      agree,
        DerivationFunction  kdf,
        Mac                 mac)
    {
        this.agree = agree;
        this.kdf = kdf;
        this.mac = mac;
        this.macBuf = new byte[mac.getMacSize()];
        this.cipher = null;
    }

    /**
     * Set up for use in conjunction with a block cipher to handle the
     * message.It is <b>strongly</b> recommended that the cipher is not in ECB mode.
     *
     * @param agree the key agreement used as the basis for the encryption
     * @param kdf the key derivation function used for byte generation
     * @param mac the message authentication code generator for the message
     * @param cipher the cipher to used for encrypting the message
     */
    public IESEngine(
        BasicAgreement      agree,
        DerivationFunction  kdf,
        Mac                 mac,
        BufferedBlockCipher cipher)
    {
        this.agree = agree;
        this.kdf = kdf;
        this.mac = mac;
        this.macBuf = new byte[mac.getMacSize()];
        this.cipher = cipher;
    }

    /**
     * Initialise the encryptor.
     *
     * @param forEncryption whether or not this is encryption/decryption.
     * @param privParam our private key parameters
     * @param pubParam the recipient's/sender's public key parameters
     * @param param encoding and derivation parameters.
     */
    public void init(
        boolean                     forEncryption,
        CipherParameters            privParam,
        CipherParameters            pubParam,
        CipherParameters            param)
    {
        this.forEncryption = forEncryption;
        this.privParam = privParam;
        this.pubParam = pubParam;
        this.param = (IESParameters)param;
    }

    private byte[] decryptBlock(
        byte[]  in_enc,
        int     inOff,
        int     inLen,
        byte[]  z)
        throws InvalidCipherTextException
    {
        byte[]          M = null;
        KeyParameter    macKey = null;
        KDFParameters   kParam = new KDFParameters(z, param.getDerivationV());
        int             macKeySize = param.getMacKeySize();

        kdf.init(kParam);

        inLen -= mac.getMacSize();

        byte[]  tmp = null;
        int     len = 0;

        // note order is important: set up keys, do simple encryptions, check mac, do final encryption.
        if (cipher == null)     // stream mode
        {
            byte[] buf = generateKdfBytes(kParam, inLen + (macKeySize / 8));

            // K2 (MAC key) from a fixed prefix, K1 (keystream) from the remainder - see encryptBlock.
            M = new byte[inLen];

            for (int i = 0; i != inLen; i++)
            {
                M[i] = (byte)(in_enc[inOff + i] ^ buf[(macKeySize / 8) + i]);
            }

            macKey = new KeyParameter(buf, 0, (macKeySize / 8));
        }
        else
        {
            int    cipherKeySize = ((IESWithCipherParameters)param).getCipherKeySize();
            byte[] buf = generateKdfBytes(kParam, (cipherKeySize / 8) + (macKeySize / 8));

            cipher.init(false, new KeyParameter(buf, 0, (cipherKeySize / 8)));

            tmp = new byte[cipher.getOutputSize(inLen)];

            // do initial processing
            len = cipher.processBytes(in_enc, inOff, inLen, tmp, 0);

            macKey = new KeyParameter(buf, (cipherKeySize / 8), (macKeySize / 8));
        }

        byte[]  macIV = param.getEncodingV();

        mac.init(macKey);
        mac.update(in_enc, inOff, inLen);
        mac.update(macIV, 0, macIV.length);
        mac.doFinal(macBuf, 0);
    
        inOff += inLen;

        byte[]  T2 = new byte[macBuf.length];
        System.arraycopy(in_enc, inOff, T2, 0, T2.length);

        if (!Arrays.constantTimeAreEqual(macBuf, T2))
        {
            throw (new InvalidCipherTextException("Mac codes failed to equal."));
        }

        if (cipher == null)
        {
            return M;
        }
        else
        {
            len += cipher.doFinal(tmp, len);

            M = new byte[len];

            System.arraycopy(tmp, 0, M, 0, len);

            return M;
        }
    }

    private byte[] encryptBlock(
        byte[]  in,
        int     inOff,
        int     inLen,
        byte[]  z)
        throws InvalidCipherTextException
    {
        byte[]          C = null;
        KeyParameter    macKey = null;
        KDFParameters   kParam = new KDFParameters(z, param.getDerivationV());
        int             c_text_length = 0;
        int             macKeySize = param.getMacKeySize();

        if (cipher == null)     // stream mode
        {
            byte[] buf = generateKdfBytes(kParam, inLen + (macKeySize / 8));

            // Derive the MAC key K2 from a fixed prefix of the KDF output and the keystream K1 from
            // the remainder. Placing K1 first (the legacy static-key layout) put K2 at a
            // message-length-dependent offset behind the keystream, so a single known-plaintext leak
            // of K1 also exposed the MAC key of any shorter message - a cross-message forgery in the
            // deterministic static-key mode. A fixed K2 offset is never covered by the keystream, closing that.
            C = new byte[inLen + mac.getMacSize()];
            c_text_length = inLen;

            for (int i = 0; i != inLen; i++)
            {
                C[i] = (byte)(in[inOff + i] ^ buf[(macKeySize / 8) + i]);
            }

            macKey = new KeyParameter(buf, 0, (macKeySize / 8));
        }
        else
        {
            int    cipherKeySize = ((IESWithCipherParameters)param).getCipherKeySize();
            byte[] buf = generateKdfBytes(kParam, (cipherKeySize / 8) + (macKeySize / 8));

            cipher.init(true, new KeyParameter(buf, 0, (cipherKeySize / 8)));

            c_text_length = cipher.getOutputSize(inLen);

            byte[] tmp = new byte[c_text_length];

            int len = cipher.processBytes(in, inOff, inLen, tmp, 0);

            len += cipher.doFinal(tmp, len);

            C = new byte[len + mac.getMacSize()];
            c_text_length = len;

            System.arraycopy(tmp, 0, C, 0, len);

            macKey = new KeyParameter(buf, (cipherKeySize / 8), (macKeySize / 8));
        }

        byte[]  macIV = param.getEncodingV();

        mac.init(macKey);
        mac.update(C, 0, c_text_length);
        mac.update(macIV, 0, macIV.length);
        //
        // return the message and it's MAC
        //
        mac.doFinal(C, c_text_length);
        return C;
    }

    private byte[] generateKdfBytes(
        KDFParameters kParam,
        int length)
    {
        byte[]  buf = new byte[length];

        kdf.init(kParam);

        kdf.generateBytes(buf, 0, buf.length);

        return buf;
    }

    public byte[] processBlock(
        byte[]  in,
        int     inOff,
        int     inLen)
        throws InvalidCipherTextException
    {
        agree.init(privParam);

        BigInteger  z = agree.calculateAgreement(pubParam);

        if (forEncryption)
        {
            return encryptBlock(in, inOff, inLen, z.toByteArray());
        }
        else
        {
            return decryptBlock(in, inOff, inLen, z.toByteArray());
        }
    }
}
