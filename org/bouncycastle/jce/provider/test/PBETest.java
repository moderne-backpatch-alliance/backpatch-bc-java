package org.bouncycastle.jce.provider.test;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * test out the various PBE modes, making sure the JCE implementations
 * are compatible woth the light weight ones.
 */
public class PBETest
    extends SimpleTest
{
    private class OpenSSLTest
        extends SimpleTest
    {
        char[]    password;
        String    baseAlgorithm;
        String    algorithm;
        int       keySize;
        int       ivSize;
        
        OpenSSLTest(
            String    baseAlgorithm,
            String    algorithm,
            int       keySize,
            int       ivSize)
        {
            this.password = algorithm.toCharArray();
            this.baseAlgorithm = baseAlgorithm;
            this.algorithm = algorithm;
            this.keySize = keySize;
            this.ivSize = ivSize;
        }
        
        public String getName()
        {
            return "OpenSSLPBE";
        }
    
        public void performTest()
            throws Exception
        {
            byte[] salt = new byte[16];
            int    iCount = 100;
            
            for (int i = 0; i != salt.length; i++)
            {
                salt[i] = (byte)i;
            }

            OpenSSLPBEParametersGenerator   pGen = new OpenSSLPBEParametersGenerator();

            pGen.init(
                    PBEParametersGenerator.PKCS5PasswordToBytes(password),
                    salt,
                    iCount);

            ParametersWithIV params = (ParametersWithIV)pGen.generateDerivedParameters(keySize, ivSize);

            SecretKeySpec   encKey = new SecretKeySpec(((KeyParameter)params.getParameters()).getKey(), baseAlgorithm);

            Cipher          c;

            if (baseAlgorithm.equals("RC4"))
            {
                c = Cipher.getInstance(baseAlgorithm, "BC");

                c.init(Cipher.ENCRYPT_MODE, encKey);
            }
            else
            {
                c = Cipher.getInstance(baseAlgorithm + "/CBC/PKCS7Padding", "BC");

                c.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(params.getIV()));
            }

            byte[]          enc = c.doFinal(salt);

            c = Cipher.getInstance(algorithm, "BC");

            PBEKeySpec          keySpec = new PBEKeySpec(password, salt, iCount);
            SecretKeyFactory    fact = SecretKeyFactory.getInstance(algorithm, "BC");

            c.init(Cipher.DECRYPT_MODE, fact.generateSecret(keySpec));

            byte[]          dec = c.doFinal(enc);

            if (!arrayEquals(salt, dec))
            {
                fail("" + algorithm + "failed encryption/decryption test");
            }
        }
    }
    
    private class PKCS12Test
        extends SimpleTest
    {
        char[]    password;
        String    baseAlgorithm;
        String    algorithm;
        Digest    digest;
        int       keySize;
        int       ivSize;
        
        PKCS12Test(
            String    baseAlgorithm,
            String    algorithm,
            Digest    digest,
            int       keySize,
            int       ivSize)
        {
            this.password = algorithm.toCharArray();
            this.baseAlgorithm = baseAlgorithm;
            this.algorithm = algorithm;
            this.digest = digest;
            this.keySize = keySize;
            this.ivSize = ivSize;
        }
        
        public String getName()
        {
            return "PKCS12PBE";
        }
    
        public void performTest()
            throws Exception
        {
            byte[] salt = new byte[digest.getDigestSize()];
            int    iCount = 100;
            
            digest.doFinal(salt, 0);

            PKCS12ParametersGenerator   pGen = new PKCS12ParametersGenerator(digest);

            pGen.init(
                    PBEParametersGenerator.PKCS12PasswordToBytes(password),
                    salt,
                    iCount);

            ParametersWithIV params = (ParametersWithIV)pGen.generateDerivedParameters(keySize, ivSize);

            SecretKeySpec   encKey = new SecretKeySpec(((KeyParameter)params.getParameters()).getKey(), baseAlgorithm);

            Cipher          c;

            if (baseAlgorithm.equals("RC4"))
            {
                c = Cipher.getInstance(baseAlgorithm, "BC");

                c.init(Cipher.ENCRYPT_MODE, encKey);
            }
            else
            {
                c = Cipher.getInstance(baseAlgorithm + "/CBC/PKCS7Padding", "BC");

                c.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(params.getIV()));
            }

            byte[]          enc = c.doFinal(salt);

            c = Cipher.getInstance(algorithm, "BC");

            PBEKeySpec          keySpec = new PBEKeySpec(password, salt, iCount);
            SecretKeyFactory    fact = SecretKeyFactory.getInstance(algorithm, "BC");

            c.init(Cipher.DECRYPT_MODE, fact.generateSecret(keySpec));

            byte[]          dec = c.doFinal(enc);

            if (!arrayEquals(salt, dec))
            {
                fail("" + algorithm + "failed encryption/decryption test");
            }

            //
            // get the parameters
            //
            AlgorithmParameters param = checkParameters(c, salt, iCount);

            //
            // try using parameters
            //
            c = Cipher.getInstance(algorithm, "BC");

            keySpec = new PBEKeySpec(password);

            c.init(Cipher.DECRYPT_MODE, fact.generateSecret(keySpec), param);

            checkParameters(c, salt, iCount);

            dec = c.doFinal(enc);

            if (!arrayEquals(salt, dec))
            {
                fail("" + algorithm + "failed encryption/decryption test");
            }

            //
            // try using PBESpec
            //
            c = Cipher.getInstance(algorithm, "BC");

            keySpec = new PBEKeySpec(password);

            c.init(Cipher.DECRYPT_MODE, fact.generateSecret(keySpec), param.getParameterSpec(PBEParameterSpec.class));

            checkParameters(c, salt, iCount);

            dec = c.doFinal(enc);

            if (!arrayEquals(salt, dec))
            {
                fail("" + algorithm + "failed encryption/decryption test");
            }
        }

        private AlgorithmParameters checkParameters(Cipher c, byte[] salt, int iCount)
            throws InvalidParameterSpecException
        {
            AlgorithmParameters param = c.getParameters();
            PBEParameterSpec spec = (PBEParameterSpec)param.getParameterSpec(PBEParameterSpec.class);

            if (!arrayEquals(salt, spec.getSalt()))
            {
                fail("" + algorithm + "failed salt test");
            }

            if (iCount != spec.getIterationCount())
            {
                fail("" + algorithm + "failed count test");
            }
            return param;
        }
    }
    
    private PKCS12Test[] pkcs12Tests = {
        new PKCS12Test("DESede", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC",  new SHA1Digest(),   192,  64),
        new PKCS12Test("DESede", "PBEWITHSHAAND2-KEYTRIPLEDES-CBC",  new SHA1Digest(),   128,  64),
        new PKCS12Test("RC4",    "PBEWITHSHAAND128BITRC4",           new SHA1Digest(),   128,   0),
        new PKCS12Test("RC4",    "PBEWITHSHAAND40BITRC4",            new SHA1Digest(),    40,   0),
        new PKCS12Test("RC2",    "PBEWITHSHAAND128BITRC2-CBC",       new SHA1Digest(),   128,  64),
        new PKCS12Test("RC2",    "PBEWITHSHAAND40BITRC2-CBC",        new SHA1Digest(),    40,  64),
        new PKCS12Test("AES",    "PBEWithSHA1And128BitAES-CBC-BC",   new SHA1Digest(),   128, 128),
        new PKCS12Test("AES",    "PBEWithSHA1And192BitAES-CBC-BC",   new SHA1Digest(),   192, 128),
        new PKCS12Test("AES",    "PBEWithSHA1And256BitAES-CBC-BC",   new SHA1Digest(),   256, 128),
        new PKCS12Test("AES",    "PBEWithSHA256And128BitAES-CBC-BC", new SHA256Digest(), 128, 128),
        new PKCS12Test("AES",    "PBEWithSHA256And192BitAES-CBC-BC", new SHA256Digest(), 192, 128),   
        new PKCS12Test("AES",    "PBEWithSHA256And256BitAES-CBC-BC", new SHA256Digest(), 256, 128),
        new PKCS12Test("Twofish","PBEWithSHAAndTwofish-CBC",         new SHA1Digest(),   256, 128),
        new PKCS12Test("IDEA",   "PBEWithSHAAndIDEA-CBC",            new SHA1Digest(),   128,  64),
        new PKCS12Test("AES",    BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes128_cbc.getId(),   new SHA1Digest(),   128, 128),
        new PKCS12Test("AES",    BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes192_cbc.getId(),   new SHA1Digest(),   192, 128),
        new PKCS12Test("AES",    BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes256_cbc.getId(),   new SHA1Digest(),   256, 128),
        new PKCS12Test("AES",    BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes128_cbc.getId(), new SHA256Digest(), 128, 128),
        new PKCS12Test("AES",    BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes192_cbc.getId(), new SHA256Digest(), 192, 128),
        new PKCS12Test("AES",    BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes256_cbc.getId(), new SHA256Digest(), 256, 128),
    };
    
    private OpenSSLTest openSSLTests[] = {
        new OpenSSLTest("AES", "PBEWITHMD5AND128BITAES-CBC-OPENSSL", 128, 128),
        new OpenSSLTest("AES", "PBEWITHMD5AND192BITAES-CBC-OPENSSL", 192, 128),
        new OpenSSLTest("AES", "PBEWITHMD5AND256BITAES-CBC-OPENSSL", 256, 128)
    };
    
    static byte[]   message = Hex.decode("4869205468657265");
    
    private byte[] hMac1 = Hex.decode("bcc42174ccb04f425d9a5c8c4a95d6fd7c372911");
    private byte[] hMac2 = Hex.decode("cb1d8bdb6aca9e3fa8980d6eb41ab28a7eb2cfd6");
    
    private Cipher makePBECipherUsingParam(
        String  algorithm,
        int     mode,
        char[]  password,
        byte[]  salt,
        int     iterationCount)
        throws Exception
    {
        PBEKeySpec          pbeSpec = new PBEKeySpec(password);
        SecretKeyFactory    keyFact = SecretKeyFactory.getInstance(algorithm, "BC");
        PBEParameterSpec    defParams = new PBEParameterSpec(salt, iterationCount);

        Cipher cipher = Cipher.getInstance(algorithm, "BC");

        cipher.init(mode, keyFact.generateSecret(pbeSpec), defParams);

        return cipher;
    }

    private Cipher makePBECipherWithoutParam(
        String  algorithm,
        int     mode,
        char[]  password,
        byte[]  salt,
        int     iterationCount)
        throws Exception
    {
        PBEKeySpec          pbeSpec = new PBEKeySpec(password, salt, iterationCount);
        SecretKeyFactory    keyFact = SecretKeyFactory.getInstance(algorithm, "BC");

        Cipher cipher = Cipher.getInstance(algorithm, "BC");

        cipher.init(mode, keyFact.generateSecret(pbeSpec));

        return cipher;
    }
    
    private boolean arrayEquals(
        byte[]  a,
        byte[]  b)
    {
        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    public void testPBEHMac(
        String  hmacName,
        byte[]  output)
    {
        SecretKey           key;
        byte[]              out;
        Mac                 mac;

        try
        {
            SecretKeyFactory    fact = SecretKeyFactory.getInstance(hmacName, "BC");

            key = fact.generateSecret(new PBEKeySpec("hello".toCharArray()));
            
            mac = Mac.getInstance(hmacName, "BC");
        }
        catch (Exception e)
        {
            fail("Failed - exception " + e.toString(), e);
            return;
        }

        try
        {
            mac.init(key, new PBEParameterSpec(new byte[20], 100));
        }
        catch (Exception e)
        {
            fail("Failed - exception " + e.toString(), e);
            return;
        }

        mac.reset();
        
        mac.update(message, 0, message.length);

        out = mac.doFinal();

        if (!arrayEquals(out, output))
        {
            fail("Failed - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
        }
    }
    
    // CVE-2026-15055, test written for the backpatch (upstream's PKCS8Test.testPbkdf2IterationCountBound targets
    // the bcpkix decryptors): PEMReader refuses a PBES2 PBKDF2 iteration count above
    // org.bouncycastle.pbe.max_iteration_count (default 10,000,000) before deriving the key. The ciphertext is filler.
    private void testPemPbes2IterationCountBound()
        throws Exception
    {
        System.setProperty("org.bouncycastle.pbe.max_iteration_count", "1000");
        try
        {
            checkPemRefused(2048, "iteration count (2048) greater than 1000");
        }
        finally
        {
            System.getProperties().remove("org.bouncycastle.pbe.max_iteration_count");
        }

        checkPemRefused(10000001, "iteration count (10000001) greater than 10000000");
    }

    private void checkPemRefused(int iterationCount, String message)
        throws Exception
    {
        PEMReader reader = new PEMReader(new StringReader(pbes2Pem(iterationCount)), new PasswordFinder()
        {
            public char[] getPassword()
            {
                return "hello".toCharArray();
            }
        });
        try
        {
            reader.readObject();
            fail("PBES2 key with iteration count " + iterationCount + " accepted");
        }
        catch (IOException e)
        {
            if (e.getMessage() == null || e.getMessage().indexOf(message) < 0)
            {
                fail("PBES2 key with iteration count " + iterationCount + ": " + e);
            }
        }
    }

    // ENCRYPTED PRIVATE KEY: PBES2 { PBKDF2 { salt, iterationCount }, des-ede3-cbc { iv } }, 16 bytes of filler
    private static String pbes2Pem(int iterationCount)
        throws IOException
    {
        ASN1EncodableVector kdfParams = new ASN1EncodableVector();
        kdfParams.add(new DEROctetString(new byte[8]));
        kdfParams.add(new DERInteger(iterationCount));
        ASN1EncodableVector kdf = new ASN1EncodableVector();
        kdf.add(PKCSObjectIdentifiers.id_PBKDF2);
        kdf.add(new DERSequence(kdfParams));
        ASN1EncodableVector enc = new ASN1EncodableVector();
        enc.add(PKCSObjectIdentifiers.des_EDE3_CBC);
        enc.add(new DEROctetString(new byte[8]));
        ASN1EncodableVector pbes2 = new ASN1EncodableVector();
        pbes2.add(new DERSequence(kdf));
        pbes2.add(new DERSequence(enc));
        ASN1EncodableVector algId = new ASN1EncodableVector();
        algId.add(PKCSObjectIdentifiers.id_PBES2);
        algId.add(new DERSequence(pbes2));
        ASN1EncodableVector info = new ASN1EncodableVector();
        info.add(new DERSequence(algId));
        info.add(new DEROctetString(new byte[16]));
        DERObject epki = new DERSequence(info);

        return "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + new String(Base64.encode(epki.getEncoded()))
            + "\n-----END ENCRYPTED PRIVATE KEY-----\n";
    }

    // CVE-2026-97873: upstream 4044aea58's PBEIterationCountTest, adapted to 1.46: no PBKDF1 parameters, no
    // raw-key PBE derivation, no PKCS12Key and no PBEWithHMacSHA256 at 1.46, and SimpleTest has no isTrue/isEquals.
    // The legacy PBES1 and PKCS#12 PBE families bound the iteration count they derive with, as PBKDF2 does, since the
    // count usually arrives in an unauthenticated parameters field and the derivation runs before anything can be
    // verified.
    private static final int TEST_MAX = 1000;

    // well above TEST_MAX, but cheap enough that a build without the bound finishes the derivation quickly
    private static final int OVER_MAX = 1000000;

    private static final byte[] SALT = new byte[8];

    private void testPBEIterationCount()
        throws Exception
    {
        String oldMax = System.getProperty("org.bouncycastle.pbe.max_iteration_count");
        System.setProperty("org.bouncycastle.pbe.max_iteration_count", Integer.toString(TEST_MAX));
        try
        {
            testIterationAlgorithmParameters();
            testIterationCipher();
            testIterationMac();
            testIterationSecretKeyFactory();
            testIterationEncryptedPrivateKeyInfo();
            testIterationWithinBound();
        }
        finally
        {
            if (oldMax == null)
            {
                System.getProperties().remove("org.bouncycastle.pbe.max_iteration_count");
            }
            else
            {
                System.setProperty("org.bouncycastle.pbe.max_iteration_count", oldMax);
            }
        }

        testIterationDefaultBound();
    }

    private void testIterationAlgorithmParameters()
        throws Exception
    {
        String[] names = { "PKCS12PBE", PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC.getId(),
            PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC.getId() };

        for (int i = 0; i != names.length; i++)
        {
            checkParamsRejected(names[i], BigInteger.valueOf(OVER_MAX), "iteration count (" + OVER_MAX + ") greater than " + TEST_MAX);
            checkParamsRejected(names[i], BigInteger.valueOf(Integer.MAX_VALUE), "iteration count (2147483647) greater than " + TEST_MAX);
            // 2^32 used to be narrowed to 0 by intValue()
            checkParamsRejected(names[i], BigInteger.valueOf(1).shiftLeft(32), "invalid iteration count (4294967296)");
            checkParamsRejected(names[i], BigInteger.valueOf(-1), "invalid iteration count (-1)");

            AlgorithmParameters params = AlgorithmParameters.getInstance(names[i], "BC");
            params.init(pbeParams(BigInteger.valueOf(TEST_MAX)));
            if (((PBEParameterSpec)params.getParameterSpec(PBEParameterSpec.class)).getIterationCount() != TEST_MAX)
            {
                fail(names[i] + ": count within the bound not kept");
            }
        }
    }

    private void checkParamsRejected(String name, BigInteger count, String message)
        throws Exception
    {
        AlgorithmParameters params = AlgorithmParameters.getInstance(name, "BC");
        try
        {
            params.init(pbeParams(count));
            fail(name + ": count " + count + " accepted");
        }
        catch (IOException e)
        {
            if (!message.equals(e.getMessage()))
            {
                fail(name + ": " + e.getMessage());
            }
        }
    }

    private void testIterationCipher()
        throws Exception
    {
        SecretKey pbeKey = pbeKey("PBEWithSHAAnd3-KeyTripleDES-CBC");

        // JCEPBEKey without derived parameters, block cipher
        checkCipherRejected("PBEWithSHAAnd3-KeyTripleDES-CBC", pbeKey, OVER_MAX);
        checkCipherRejected("PBEWithSHAAnd3-KeyTripleDES-CBC", pbeKey, -1);
        // PBES1 (PKCS#5 scheme 1)
        checkCipherRejected("PBEWithMD5AndDES", pbeKey("PBEWithMD5AndDES"), OVER_MAX);
        // stream cipher
        checkCipherRejected("PBEWithSHAAnd128BitRC4", pbeKey("PBEWithSHAAnd128BitRC4"), OVER_MAX);
    }

    private void checkCipherRejected(String name, SecretKey key, int count)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance(name, "BC");
        try
        {
            cipher.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(SALT, count));
            fail(name + ": count " + count + " accepted");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            if (!isIterationCountMessage(e.getMessage()))
            {
                fail(name + ": " + e.getMessage());
            }
        }
    }

    private void testIterationMac()
        throws Exception
    {
        Mac mac = Mac.getInstance("PBEWithHMacSHA1", "BC");
        try
        {
            mac.init(pbeKey("PBEWithHMacSHA1"), new PBEParameterSpec(SALT, OVER_MAX));
            fail("PBEWithHMacSHA1: count accepted");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            if (!isIterationCountMessage(e.getMessage()))
            {
                fail("PBEWithHMacSHA1: " + e.getMessage());
            }
        }
    }

    private void testIterationSecretKeyFactory()
        throws Exception
    {
        // the PBE key factory (PKCS#12 cipher and MAC), and the DES key factory's own derivation (PBES1)
        String[] names = { "PBEWithSHAAnd3-KeyTripleDES-CBC", "PBEWithHMacSHA1", "PBEWithMD5AndDES" };

        for (int i = 0; i != names.length; i++)
        {
            SecretKeyFactory fact = SecretKeyFactory.getInstance(names[i], "BC");
            try
            {
                fact.generateSecret(new PBEKeySpec("password".toCharArray(), SALT, OVER_MAX, 64));
                fail(names[i] + ": count accepted");
            }
            catch (InvalidKeySpecException e)
            {
                if (!isIterationCountMessage(e.getMessage()))
                {
                    fail(names[i] + ": " + e.getMessage());
                }
            }
        }
    }

    /**
     * The report's end-to-end case: EncryptedPrivateKeyInfo.getKeySpec() on a PKCS#12 PBE blob, where the JDK's own
     * provider decodes the parameters and BC's Cipher only ever sees the resulting PBEParameterSpec.
     */
    private void testIterationEncryptedPrivateKeyInfo()
        throws Exception
    {
        DERObjectIdentifier[] oids = { PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC,
            PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC };

        for (int i = 0; i != oids.length; i++)
        {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new AlgorithmIdentifier(oids[i], ASN1Object.fromByteArray(pbeParams(BigInteger.valueOf(OVER_MAX)))));
            v.add(new DEROctetString(new byte[24]));
            byte[] encoding = new DERSequence(v).getEncoded();

            try
            {
                EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(encoding);
                epki.getKeySpec(pbeKey("PBEWithSHAAnd3-KeyTripleDES-CBC"), "BC");
                fail(oids[i] + ": key spec returned");
            }
            catch (Exception e)
            {
                if (!hasIterationCountCause(e))
                {
                    fail(oids[i] + ": " + e);
                }
            }
        }
    }

    private void testIterationWithinBound()
        throws Exception
    {
        SecretKey key = pbeKey("PBEWithSHAAnd3-KeyTripleDES-CBC");
        byte[] data = "hello world!".getBytes("US-ASCII");

        int[] counts = { 0, 1, TEST_MAX };
        for (int i = 0; i != counts.length; i++)
        {
            PBEParameterSpec spec = new PBEParameterSpec(SALT, counts[i]);

            Cipher cipher = Cipher.getInstance("PBEWithSHAAnd3-KeyTripleDES-CBC", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            byte[] ct = cipher.doFinal(data);

            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            if (!Arrays.areEqual(data, cipher.doFinal(ct)))
            {
                fail("count " + counts[i]);
            }

            Mac mac = Mac.getInstance("PBEWithHMacSHA1", "BC");
            mac.init(pbeKey("PBEWithHMacSHA1"), spec);
            mac.doFinal(data);

            if (counts[i] > 0)      // PBEKeySpec itself refuses a zero count
            {
                SecretKeyFactory.getInstance("PBEWithSHAAnd3-KeyTripleDES-CBC", "BC")
                    .generateSecret(new PBEKeySpec("password".toCharArray(), SALT, counts[i], 192));
            }
        }
    }

    private void testIterationDefaultBound()
        throws Exception
    {
        AlgorithmParameters params = AlgorithmParameters.getInstance("PKCS12PBE", "BC");
        params.init(pbeParams(BigInteger.valueOf(10000000)));

        params = AlgorithmParameters.getInstance("PKCS12PBE", "BC");
        try
        {
            params.init(pbeParams(BigInteger.valueOf(10000001)));
            fail("PKCS12PBE: default bound not applied");
        }
        catch (IOException e)
        {
            if (!"iteration count (10000001) greater than 10000000".equals(e.getMessage()))
            {
                fail("PKCS12PBE: " + e.getMessage());
            }
        }

        Cipher cipher = Cipher.getInstance("PBEWithSHAAnd3-KeyTripleDES-CBC", "BC");
        try
        {
            cipher.init(Cipher.DECRYPT_MODE, pbeKey("PBEWithSHAAnd3-KeyTripleDES-CBC"), new PBEParameterSpec(SALT, Integer.MAX_VALUE));
            fail("default bound not applied");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            if (!"iteration count (2147483647) greater than 10000000".equals(e.getMessage()))
            {
                fail("default bound: " + e.getMessage());
            }
        }
    }

    private static SecretKey pbeKey(String algorithm)
        throws Exception
    {
        return SecretKeyFactory.getInstance(algorithm, "BC").generateSecret(new PBEKeySpec("password".toCharArray()));
    }

    // PKCS12PBEParams and PBEParameter share the SEQUENCE { OCTET STRING, INTEGER } shape
    private static byte[] pbeParams(BigInteger count)
        throws Exception
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DEROctetString(SALT));
        v.add(new DERInteger(count));
        return new DERSequence(v).getEncoded();
    }

    private static boolean isIterationCountMessage(String message)
    {
        return message != null && message.indexOf("iteration count") >= 0;
    }

    private static boolean hasIterationCountCause(Throwable t)
    {
        for (; t != null; t = t.getCause())
        {
            if (isIterationCountMessage(t.getMessage()))
            {
                return true;
            }
        }
        return false;
    }

    public void performTest()
        throws Exception
    {
        testPemPbes2IterationCountBound();
        testPBEIterationCount();

        byte[] input = Hex.decode("1234567890abcdefabcdef1234567890fedbca098765");

        //
        // DES
        //
        Cipher  cEnc = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");

        cEnc.init(Cipher.ENCRYPT_MODE,
            new SecretKeySpec(Hex.decode("30e69252758e5346"), "DES"),
            new IvParameterSpec(Hex.decode("7c1c1ab9c454a688")));

        byte[]  out = cEnc.doFinal(input);

        char[]  password = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };

        Cipher  cDec = makePBECipherUsingParam(
                            "PBEWithSHA1AndDES",
                            Cipher.DECRYPT_MODE,
                            password,
                            Hex.decode("7d60435f02e9e0ae"),
                            2048);

        byte[]  in = cDec.doFinal(out);

        if (!arrayEquals(input, in))
        {
            fail("DES failed");
        }

        cDec = makePBECipherWithoutParam(
                "PBEWithSHA1AndDES",
                Cipher.DECRYPT_MODE,
                password,
                Hex.decode("7d60435f02e9e0ae"),
                2048);

        in = cDec.doFinal(out);
        
        if (!arrayEquals(input, in))
        {
            fail("DES failed without param");
        }
        
        //
        // DESede
        //
        cEnc = Cipher.getInstance("DESede/CBC/PKCS7Padding", "BC");

        cEnc.init(Cipher.ENCRYPT_MODE,
            new SecretKeySpec(Hex.decode("732f2d33c801732b7206756cbd44f9c1c103ddd97c7cbe8e"), "DES"),
            new IvParameterSpec(Hex.decode("b07bf522c8d608b8")));

        out = cEnc.doFinal(input);

        cDec = makePBECipherUsingParam(
                            "PBEWithSHAAnd3-KeyTripleDES-CBC",
                            Cipher.DECRYPT_MODE,
                            password,
                            Hex.decode("7d60435f02e9e0ae"),
                            2048);

        in = cDec.doFinal(out);

        if (!arrayEquals(input, in))
        {
            fail("DESede failed");
        }

        //
        // 40Bit RC2
        //
        cEnc = Cipher.getInstance("RC2/CBC/PKCS7Padding", "BC");

        cEnc.init(Cipher.ENCRYPT_MODE,
            new SecretKeySpec(Hex.decode("732f2d33c8"), "RC2"),
            new IvParameterSpec(Hex.decode("b07bf522c8d608b8")));

        out = cEnc.doFinal(input);

        cDec = makePBECipherUsingParam(
                            "PBEWithSHAAnd40BitRC2-CBC",
                            Cipher.DECRYPT_MODE,
                            password,
                            Hex.decode("7d60435f02e9e0ae"),
                            2048);

        in = cDec.doFinal(out);

        if (!arrayEquals(input, in))
        {
            fail("RC2 failed");
        }

        //
        // 128bit RC4
        //
        cEnc = Cipher.getInstance("RC4", "BC");

        cEnc.init(Cipher.ENCRYPT_MODE,
            new SecretKeySpec(Hex.decode("732f2d33c801732b7206756cbd44f9c1"), "RC4"));

        out = cEnc.doFinal(input);

        cDec = makePBECipherUsingParam(
                            "PBEWithSHAAnd128BitRC4",
                            Cipher.DECRYPT_MODE,
                            password,
                            Hex.decode("7d60435f02e9e0ae"),
                            2048);

        in = cDec.doFinal(out);

        if (!arrayEquals(input, in))
        {
            fail("RC4 failed");
        }

        cDec = makePBECipherWithoutParam(
                "PBEWithSHAAnd128BitRC4",
                Cipher.DECRYPT_MODE,
                password,
                Hex.decode("7d60435f02e9e0ae"),
                2048);

        in = cDec.doFinal(out);
        
        if (!arrayEquals(input, in))
        {
            fail("RC4 failed without param");
        }

        for (int i = 0; i != pkcs12Tests.length; i++)
        {
            pkcs12Tests[i].perform();
        }
        
        for (int i = 0; i != openSSLTests.length; i++)
        {
            openSSLTests[i].perform();
        }

        testPBEHMac("PBEWithHMacSHA1", hMac1);
        testPBEHMac("PBEWithHMacRIPEMD160", hMac2);
    }

    public String getName()
    {
        return "PBETest";
    }


    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PBETest());
    }
}
