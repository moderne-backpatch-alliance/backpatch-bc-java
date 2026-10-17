package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.IESParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * test for ECIES - Elliptic Curve Integrated Encryption Scheme
 */
public class IESTest
    extends SimpleTest
{
    private BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
    private BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

    IESTest()
    {
    }

    public String getName()
    {
        return "IES";
    }

    // CVE-2026-12816: upstream 6d9e4bbae's ECIESTest.doForgeryTest, in the provider IESTest (1.46 ships no crypto
    // tests); 1.46's ECCurve.Fp takes no order and cofactor, and its IESEngine needs a non-null encoding vector
    // (an empty one gives the same MAC input as upstream's null).
    //
    // Regression for CVD ANT-2026-WZ2GJBGD: in static-key stream mode the MAC key must not be
    // recoverable from the keystream. The legacy layout placed the keystream K1 before the MAC key
    // K2, so a single known-plaintext leak of K1 (= M ^ C) also exposed the MAC key of any shorter
    // message - letting an attacker forge a valid ciphertext+tag from one observation. With K2 now
    // taken from a fixed prefix of the KDF output, that slice of the leaked keystream is no longer
    // the MAC key, so the constructed forgery must be rejected.
    private void doForgeryTest()
        throws Exception
    {
        BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
            new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16)); // b

        ECDomainParameters params = new ECDomainParameters(curve,
                curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), n);

        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("651056770906015076056810763456358567190100156695615665659"), params);
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), params);

        AsymmetricCipherKeyPair p1 = new AsymmetricCipherKeyPair(pubKey, priKey);
        AsymmetricCipherKeyPair p2 = new AsymmetricCipherKeyPair(pubKey, priKey);

        int macKeyBytes = 8; // 64-bit MAC key
        // empty encoding vector, so the MAC is taken over the ciphertext only (keeps the forgery construction simple)
        IESParameters param = new IESParameters(new byte[]{ 1, 2, 3, 4, 5, 6, 7, 8 }, new byte[0], macKeyBytes * 8);

        // 1. attacker observes one known-plaintext ciphertext of length L (>= macKeyBytes)
        byte[] knownPt = Hex.decode("000102030405060708090a0b0c0d0e0f10111213"); // L = 20
        IESEngine enc = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()));
        enc.init(true, p1.getPrivate(), p2.getPublic(), param);
        byte[] ct = enc.processBlock(knownPt, 0, knownPt.length);

        byte[] leaked = new byte[knownPt.length]; // recovered keystream = M ^ C over the L plaintext bytes
        for (int i = 0; i != leaked.length; i++)
        {
            leaked[i] = (byte)(knownPt[i] ^ ct[i]);
        }

        // 2. forge a shorter message, assuming the legacy keystream-then-MAC-key layout
        int forgeLen = knownPt.length - macKeyBytes; // L'
        byte[] forgedPt = Hex.decode("ffffffffffffffffffffffff"); // 12 bytes (= L')
        byte[] forgedC = new byte[forgeLen];
        for (int i = 0; i != forgeLen; i++)
        {
            forgedC[i] = (byte)(forgedPt[i] ^ leaked[i]); // K1' = leaked[0..L']
        }

        HMac hmac = new HMac(new SHA1Digest());
        byte[] k2 = new byte[macKeyBytes];
        System.arraycopy(leaked, forgeLen, k2, 0, macKeyBytes);
        hmac.init(new KeyParameter(k2)); // K2' = leaked[L'..]
        hmac.update(forgedC, 0, forgedC.length);
        byte[] forgedTag = new byte[hmac.getMacSize()];
        hmac.doFinal(forgedTag, 0);

        byte[] forged = new byte[forgedC.length + forgedTag.length];
        System.arraycopy(forgedC, 0, forged, 0, forgedC.length);
        System.arraycopy(forgedTag, 0, forged, forgedC.length, forgedTag.length);

        // 3. the recipient must reject the forgery
        IESEngine dec = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()));
        dec.init(false, p2.getPrivate(), p1.getPublic(), param);
        try
        {
            dec.processBlock(forged, 0, forged.length);
            fail("static-key stream IES accepted a cross-message MAC forgery");
        }
        catch (InvalidCipherTextException expected)
        {
            // expected: K2 is a fixed prefix of the KDF output, not a recoverable slice of the keystream
        }

        // the genuine ciphertext still decrypts
        if (!Arrays.areEqual(knownPt, dec.processBlock(ct, 0, ct.length)))
        {
            fail("static-key stream IES round trip failed");
        }
    }

    public void performTest()
        throws Exception
    {
        doForgeryTest();

        KeyPairGenerator    g = KeyPairGenerator.getInstance("ECIES", "BC");

        ECCurve curve = new ECCurve.Fp(
                new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
                new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

        ECParameterSpec ecSpec = new ECParameterSpec(
                curve,
                curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n

        g.initialize(ecSpec, new SecureRandom());

        Cipher c1 = Cipher.getInstance("ECIES", "BC");
        Cipher c2 = Cipher.getInstance("ECIES", "BC");
        
        doTest(g, c1, c2);

        g = KeyPairGenerator.getInstance("ECIES", "BC");

        g.initialize(192, new SecureRandom());

        doTest(g, c1, c2);

        g = KeyPairGenerator.getInstance("ECIES", "BC");

        g.initialize(239, new SecureRandom());

        doTest(g, c1, c2);

        g = KeyPairGenerator.getInstance("ECIES", "BC");

        g.initialize(256, new SecureRandom());

        doTest(g, c1, c2);

        doDefTest(g, c1, c2);
        
        DHParameterSpec             dhParams = new DHParameterSpec(p512, g512);
        
        c1 = Cipher.getInstance("IES", "BC");
        c2 = Cipher.getInstance("IES", "BC");
        
        g = KeyPairGenerator.getInstance("DH", "BC");

        g.initialize(dhParams);
        
        doTest(g, c1, c2);
        
        doDefTest(g, c1, c2);
    }

    public void doTest(
        KeyPairGenerator g,
        Cipher           c1,
        Cipher           c2)
        throws Exception
    {
        //
        // a side
        //
        KeyPair     aKeyPair = g.generateKeyPair();
        PublicKey   aPub = aKeyPair.getPublic();
        PrivateKey  aPriv = aKeyPair.getPrivate();

        //
        // b side
        //
        KeyPair     bKeyPair = g.generateKeyPair();
        PublicKey   bPub = bKeyPair.getPublic();
        PrivateKey  bPriv = bKeyPair.getPrivate();

        //
        // stream test
        //

        IEKeySpec   c1Key = new IEKeySpec(aPriv, bPub);
        IEKeySpec   c2Key = new IEKeySpec(bPriv, aPub);

        byte[]  d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        byte[]  e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };

        IESParameterSpec param = new IESParameterSpec(d, e, 128);

        c1.init(Cipher.ENCRYPT_MODE, c1Key, param);

        c2.init(Cipher.DECRYPT_MODE, c2Key, param);

        byte[] message = Hex.decode("1234567890abcdef");

        byte[]   out1 = c1.doFinal(message, 0, message.length);

        byte[]   out2 = c2.doFinal(out1, 0, out1.length);

        if (!areEqual(out2, message))
        {
            fail("stream cipher test failed");
        }
    }

    public void doDefTest(
        KeyPairGenerator    g,
        Cipher              c1,
        Cipher              c2)
        throws Exception
    {
        //
        // a side
        //
        KeyPair     aKeyPair = g.generateKeyPair();
        PublicKey   aPub = aKeyPair.getPublic();
        PrivateKey  aPriv = aKeyPair.getPrivate();

        //
        // b side
        //
        KeyPair     bKeyPair = g.generateKeyPair();
        PublicKey   bPub = bKeyPair.getPublic();
        PrivateKey  bPriv = bKeyPair.getPrivate();

        //
        // stream test
        //
        IEKeySpec   c1Key = new IEKeySpec(aPriv, bPub);
        IEKeySpec   c2Key = new IEKeySpec(bPriv, aPub);

        c1.init(Cipher.ENCRYPT_MODE, c1Key);

        AlgorithmParameters param = c1.getParameters();

        c2.init(Cipher.DECRYPT_MODE, c2Key, param);

        byte[] message = Hex.decode("1234567890abcdef");

        byte[] out1 = c1.doFinal(message, 0, message.length);

        byte[] out2 = c2.doFinal(out1, 0, out1.length);

        if (!areEqual(out2, message))
        {
            fail("stream cipher test failed");
        }
        
        //
        // int doFinal
        //
        int len1 = c1.doFinal(message, 0, message.length, out1, 0);
        
        if (len1 != out1.length)
        {
            fail("encryption length wrong");
        }
        
        int len2 = c2.doFinal(out1, 0, out1.length, out2, 0);

        if (len2 != out2.length)
        {
            fail("decryption length wrong");
        }
        
        if (!areEqual(out2, message))
        {
            fail("stream cipher test failed");
        }
        
        //
        // int doFinal with update
        //
        len1 = c1.update(message, 0, 2, out1, 0);
        
        len1 += c1.doFinal(message, 2, message.length - 2, out1, len1);
        
        if (len1 != out1.length)
        {
            fail("update encryption length wrong");
        }
        
        len2 = c2.update(out1, 0, 2, out2, 0);
        
        len2 += c2.doFinal(out1, 2, out1.length - 2, out2, len2);

        if (len2 != out2.length)
        {
            fail("update decryption length wrong");
        }
        
        if (!areEqual(out2, message))
        {
            fail("update stream cipher test failed");
        }
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new IESTest());
    }
}
