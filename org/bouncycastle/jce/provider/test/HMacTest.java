package org.bouncycastle.jce.provider.test;

import java.lang.reflect.Field;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.RC5ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.tls.ContentType;
import org.bouncycastle.crypto.tls.SecurityParameters;
import org.bouncycastle.crypto.tls.TlsBlockCipher;
import org.bouncycastle.crypto.tls.TlsClientContext;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
import org.bouncycastle.crypto.tls.TlsMac;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * HMAC tester
 */
public class HMacTest
    extends SimpleTest
{
    static byte[]   keyBytes = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    static byte[]   message = "Hi There".getBytes();
    static byte[]   output1 = Hex.decode("b617318655057264e28bc0b6fb378c8ef146be00");
    static byte[]   outputMD5 = Hex.decode("5ccec34ea9656392457fa1ac27f08fbc");
    static byte[]   outputMD2 = Hex.decode("dc1923ef5f161d35bef839ca8c807808");
    static byte[]   outputMD4 = Hex.decode("5570ce964ba8c11756cdc3970278ff5a");
    static byte[]   output224 = Hex.decode("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22");
    static byte[]   output256 = Hex.decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    static byte[]   output384 = Hex.decode("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
    static byte[]   output512 = Hex.decode("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    static byte[]   outputRipeMD128 = Hex.decode("fda5717fb7e20cf05d30bb286a44b05d");
    static byte[]   outputRipeMD160 = Hex.decode("24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668");
    static byte[]   outputTiger = Hex.decode("1d7a658c75f8f004916e7b07e2a2e10aec7de2ae124d3647");
    static byte[]   outputOld384 = Hex.decode("0a046aaa0255e432912228f8ccda437c8a8363fb160afb0570ab5b1fd5ddc20eb1888b9ed4e5b6cb5bc034cd9ef70e40");
    static byte[]   outputOld512 = Hex.decode("9656975ee5de55e75f2976ecce9a04501060b9dc22a6eda2eaef638966280182477fe09f080b2bf564649cad42af8607a2bd8d02979df3a980f15e2326a0a22a");

    public HMacTest()
    {
    }

    public void testHMac(
        String  hmacName,
        byte[]  output)
        throws Exception
    {
        SecretKey           key = new SecretKeySpec(keyBytes, hmacName);
        byte[]              out;
        Mac                 mac;

        mac = Mac.getInstance(hmacName, "BC");

        mac.init(key);

        mac.reset();

        mac.update(message, 0, message.length);

        out = mac.doFinal();

        if (!areEqual(out, output))
        {
            fail("Failed - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
        }

        // no key generator for the old algorithms
        if (hmacName.startsWith("Old"))
        {
            return;
        }

        KeyGenerator kGen = KeyGenerator.getInstance(hmacName, "BC");

        mac.init(kGen.generateKey());

        mac.update(message);

        out = mac.doFinal();
    }

    private void testExceptions()
        throws Exception
    {
        Mac mac = null;

        mac = Mac.getInstance("HmacSHA1", "BC");

        byte [] b = {(byte)1, (byte)2, (byte)3, (byte)4, (byte)5};
        SecretKeySpec sks = new SecretKeySpec(b, "HmacSHA1");
        RC5ParameterSpec algPS = new RC5ParameterSpec(100, 100, 100);

        try
        {
            mac.init(sks, algPS);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // ignore okay
        }

        try
        {
            mac.init(null, null);
        }
        catch (InvalidKeyException e)
        {
            // ignore okay
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // ignore okay
        }

        try
        {
            mac.init(null);
        }
        catch (InvalidKeyException e)
        {
            // ignore okay
        }
    }

    // test written for the backpatch (CVE-2013-1624, "Lucky Thirteen"): TlsBlockCipher.decodeCiphertext runs the
    // same number of SHA-1 compressions for records of the same length, whatever their padding length and whether
    // the padding is valid
    private void testTlsRecordMacConstantTime()
        throws Exception
    {
        SecurityParameters securityParameters = new SecurityParameters();
        setField(SecurityParameters.class, securityParameters, "masterSecret", new byte[48]);
        setField(SecurityParameters.class, securityParameters, "clientRandom", new byte[32]);
        setField(SecurityParameters.class, securityParameters, "serverRandom", new byte[32]);
        final SecurityParameters sp = securityParameters;
        TlsClientContext context = new TlsClientContext()
        {
            private final SecureRandom random = new SecureRandom();
            private Object userObject;

            public SecureRandom getSecureRandom()
            {
                return random;
            }

            public SecurityParameters getSecurityParameters()
            {
                return sp;
            }

            public Object getUserObject()
            {
                return userObject;
            }

            public void setUserObject(Object userObject)
            {
                this.userObject = userObject;
            }
        };

        TlsBlockCipher tlsCipher = new TlsBlockCipher(context, new CBCBlockCipher(new AESEngine()),
            new CBCBlockCipher(new AESEngine()), new SHA1Digest(), new SHA1Digest(), 16);

        byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] iv = Hex.decode("0f0e0d0c0b0a09080706050403020100");
        byte[] macKey = Hex.decode("101112131415161718191a1b1c1d1e1f20212223");

        // 64-byte records: 42 bytes of data with a 2-byte pad, 43 bytes with a 1-byte pad, and 43 bytes with a
        // wrong pad byte; the MAC input crosses a SHA-1 block boundary between 42 and 43 bytes
        int[] counts = new int[3];
        for (int r = 0; r != counts.length; r++)
        {
            int dataLen = (r == 0) ? 42 : 43;
            byte[] data = new byte[dataLen];
            for (int i = 0; i != data.length; i++)
            {
                data[i] = (byte)i;
            }

            byte[] mac = new TlsMac(new SHA1Digest(), macKey, 0, macKey.length).calculateMac(ContentType.application_data, data, 0, data.length);
            byte[] record = new byte[64];
            System.arraycopy(data, 0, record, 0, data.length);
            System.arraycopy(mac, 0, record, data.length, mac.length);
            int pad = record.length - data.length - mac.length - 1;
            for (int i = data.length + mac.length; i != record.length; i++)
            {
                record[i] = (byte)pad;
            }
            if (r == 2)
            {
                record[record.length - 1] = 7;
            }

            BlockCipher enc = new CBCBlockCipher(new AESEngine());
            enc.init(true, new ParametersWithIV(new KeyParameter(key), iv));
            for (int i = 0; i < record.length; i += 16)
            {
                enc.processBlock(record, i, record, i);
            }

            CountingSHA1Digest counting = new CountingSHA1Digest();
            setField(TlsBlockCipher.class, tlsCipher, "readMac", new TlsMac(counting, macKey, 0, macKey.length));
            BlockCipher dec = new CBCBlockCipher(new AESEngine());
            dec.init(false, new ParametersWithIV(new KeyParameter(key), iv));
            setField(TlsBlockCipher.class, tlsCipher, "decryptCipher", dec);

            counting.blocks = 0;
            try
            {
                byte[] plain = tlsCipher.decodeCiphertext(ContentType.application_data, record, 0, record.length);
                if (r == 2 || !Arrays.areEqual(data, plain))
                {
                    fail("TLS record " + r + " decoded wrongly");
                }
            }
            catch (TlsFatalAlert e)
            {
                if (r != 2)
                {
                    fail("TLS record " + r + " refused");
                }
            }
            counts[r] = counting.blocks;
        }

        if (counts[0] != counts[1] || counts[1] != counts[2])
        {
            fail("SHA-1 compressions differ for equal-length TLS records: " + counts[0] + ", " + counts[1] + ", " + counts[2]);
        }
    }

    private static void setField(Class cls, Object target, String name, Object value)
        throws Exception
    {
        Field f = cls.getDeclaredField(name);
        f.setAccessible(true);
        f.set(target, value);
    }

    private static class CountingSHA1Digest
        extends SHA1Digest
    {
        int blocks;

        protected void processBlock()
        {
            blocks++;
            super.processBlock();
        }
    }

    public void performTest()
        throws Exception
    {
        testTlsRecordMacConstantTime();

        testHMac("HMac-SHA1", output1);
        testHMac("HMac-MD5", outputMD5);
        testHMac("HMac-MD4", outputMD4);
        testHMac("HMac-MD2", outputMD2);
        testHMac("HMac-SHA224", output224);
        testHMac("HMac-SHA256", output256);
        testHMac("HMac-SHA384", output384);
        testHMac("HMac-SHA512", output512);
        testHMac("HMac-RIPEMD128", outputRipeMD128);
        testHMac("HMac-RIPEMD160", outputRipeMD160);
        testHMac("HMac-TIGER", outputTiger);

        testHMac("HMac/SHA1", output1);
        testHMac("HMac/MD5", outputMD5);
        testHMac("HMac/MD4", outputMD4);
        testHMac("HMac/MD2", outputMD2);
        testHMac("HMac/SHA224", output224);
        testHMac("HMac/SHA256", output256);
        testHMac("HMac/SHA384", output384);
        testHMac("HMac/SHA512", output512);
        testHMac("HMac/RIPEMD128", outputRipeMD128);
        testHMac("HMac/RIPEMD160", outputRipeMD160);
        testHMac("HMac/TIGER", outputTiger);

        testHMac(PKCSObjectIdentifiers.id_hmacWithSHA1.getId(), output1);
        testHMac(PKCSObjectIdentifiers.id_hmacWithSHA224.getId(), output224);
        testHMac(PKCSObjectIdentifiers.id_hmacWithSHA256.getId(), output256);
        testHMac(PKCSObjectIdentifiers.id_hmacWithSHA384.getId(), output384);
        testHMac(PKCSObjectIdentifiers.id_hmacWithSHA512.getId(), output512);
        testHMac(IANAObjectIdentifiers.hmacSHA1.getId(), output1);
        testHMac(IANAObjectIdentifiers.hmacMD5.getId(), outputMD5);
        testHMac(IANAObjectIdentifiers.hmacRIPEMD160.getId(), outputRipeMD160);
        testHMac(IANAObjectIdentifiers.hmacTIGER.getId(), outputTiger);

        // test for compatibility with broken HMac.
        testHMac("OldHMacSHA384", outputOld384);
        testHMac("OldHMacSHA512", outputOld512);

        testExceptions();
    }

    public String getName()
    {
        return "HMac";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new HMacTest());
    }
}
