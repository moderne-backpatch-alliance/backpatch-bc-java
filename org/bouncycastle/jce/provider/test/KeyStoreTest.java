package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 * Exercise the various key stores, making sure we at least get back what we put in!
 * <p>
 * This tests both the BKS, and the UBER key store.
 */
public class KeyStoreTest
    extends SimpleTest
{
    static char[]   passwd = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' };

    byte[] v1BKS = Base64.decode(
          "AAAAAQAAABTqZbNMyPjsFazhFplWWDMBLPRdRAAABcYEAAdhbmRyb2lkAAAB"
        + "NOifkPwAAAAAAAAAPAAAABTZOLhcyhB0gKyfoDvyQbpzftB7GgAABEYPrZP8"
        + "q20AJLETjDv0K9C5rIl1erpyvpv20bqcbghK6wD0b8OP5/XzOz/8knhxmqJZ"
        + "3yRJMw==");
    byte[] v2BKS = Base64.decode(
          "AAAAAgAAABSkmTXz4VIznO1SSUqsIHdxWcxsuQAABFMEAAdhbmRyb2lkAAABN" +
          "OifkPwAAAAAAAAAPAAAABTZOLhcyhB0gKyfoDvyQbpzftB7GgAABEYPrZP8q2" +
          "0AJLETjDv0K9C5rIl1erpyvpv20bqcbghK6wBO59KOGPvSrmJpd32P6ZAh9qLZJw==");

    byte[] v1UBER = Base64.decode(
          "AAAAAQAAABRP0F6p2p3FyQKqyJiJt3NbvdybiwAAB2znqrO779YIW5gMtbt+"
        + "NUs96VPPcfZiKJPg7RKH7Yu3CQB0/g9nYsvgFB0fQ05mHcW3KjntN2/31A6G"
        + "i00n4ZnUTjJL16puZnQrloeGXxFy58tjwkFuwJ7V7ELYgiZlls0beHSdDGQW"
        + "iyYECwWs1la/");
    byte[] v2UBER = Base64.decode(
          "AAAAAgAAABQ/D9k3376OG/REg4Ams9Up332tLQAABujoVcsRcKWwhlo4mMg5"
        + "lF2vJfK+okIYecJGWCvdykF5r8kDn68llt52IDXDkpRXVXcNJ0/aD7sa7iZ0"
        + "SL0TAwcfp/9v4j/w8slj/qgO0i/76+zROrP0NGFIa5k/iOg5Z0Tj77muMaJf"
        + "n3vLlIHa4IsX");

    char[] oldStorePass = "fredfred".toCharArray();

    public void ecStoreTest(
        String  storeName)
        throws Exception
    {
        ECCurve curve = new ECCurve.Fp(
                                new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
                                new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                                new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

        ECParameterSpec ecSpec = new ECParameterSpec(
                                curve,
                                curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                                new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n

        KeyPairGenerator    g = KeyPairGenerator.getInstance("ECDSA", "BC");

        g.initialize(ecSpec, new SecureRandom());

        KeyPair     keyPair = g.generateKeyPair();

        PublicKey   pubKey = keyPair.getPublic();
        PrivateKey  privKey = keyPair.getPrivate();

        //
        // distinguished name table.
        //
        Hashtable                 attrs = new Hashtable();
        Vector                    order = new Vector();

        attrs.put(X509Principal.C, "AU");
        attrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
        attrs.put(X509Principal.L, "Melbourne");
        attrs.put(X509Principal.ST, "Victoria");
        attrs.put(X509Principal.E, "feedback-crypto@bouncycastle.org");

        order.addElement(X509Principal.C);
        order.addElement(X509Principal.O);
        order.addElement(X509Principal.L);
        order.addElement(X509Principal.ST);
        order.addElement(X509Principal.E);

        //
        // create the certificate - version 3
        //
        X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(new X509Principal(order, attrs));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(new X509Principal(order, attrs));
        certGen.setPublicKey(pubKey);
        certGen.setSignatureAlgorithm("ECDSAwithSHA1");

        Certificate[]    chain = new Certificate[1];

        try
        {
            X509Certificate cert = certGen.generate(privKey);

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
            CertificateFactory      fact = CertificateFactory.getInstance("X.509", "BC");

            cert = (X509Certificate)fact.generateCertificate(bIn);

            chain[0] = cert;
        }
        catch (Exception e)
        {
            fail("error generating cert - " + e.toString());
        }

        KeyStore store = KeyStore.getInstance(storeName, "BC");

        store.load(null, null);

        store.setKeyEntry("private", privKey, passwd, chain);

        //
        // write out and read back store
        //
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();

        store.store(bOut, passwd);

        ByteArrayInputStream    bIn = new ByteArrayInputStream(bOut.toByteArray());

        //
        // start with a new key store
        //
        store = KeyStore.getInstance(storeName, "BC");

        store.load(bIn, passwd);

        //
        // load the private key
        //
        privKey = (PrivateKey)store.getKey("private", passwd);

        //
        // double public key encoding test
        //
        byte[]              pubEnc = pubKey.getEncoded();
        KeyFactory          keyFac = KeyFactory.getInstance(pubKey.getAlgorithm(), "BC");
        X509EncodedKeySpec  pubX509 = new X509EncodedKeySpec(pubEnc);

        pubKey = (PublicKey)keyFac.generatePublic(pubX509);

        pubEnc = pubKey.getEncoded();
        keyFac = KeyFactory.getInstance(pubKey.getAlgorithm(), "BC");
        pubX509 = new X509EncodedKeySpec(pubEnc);

        pubKey = (PublicKey)keyFac.generatePublic(pubX509);

        //
        // double private key encoding test
        //
        byte[]              privEnc = privKey.getEncoded();

        keyFac = KeyFactory.getInstance(privKey.getAlgorithm(), "BC");

        PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
        privKey = (PrivateKey)keyFac.generatePrivate(privPKCS8);

        keyFac = KeyFactory.getInstance(privKey.getAlgorithm(), "BC");
        privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
        privKey = (PrivateKey)keyFac.generatePrivate(privPKCS8);
    }

    public void keyStoreTest(
        String    storeName)
        throws Exception
    {
        KeyStore store = KeyStore.getInstance(storeName, "BC");

        store.load(null, null);

        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");

        gen.initialize(1024, new SecureRandom());

        KeyPair         pair = gen.generateKeyPair();
        RSAPrivateKey   privKey = (RSAPrivateKey)pair.getPrivate();
        RSAPublicKey    pubKey = (RSAPublicKey)pair.getPublic();
        BigInteger      modulus = privKey.getModulus();
        BigInteger      privateExponent = privKey.getPrivateExponent();


        //
        // distinguished name table.
        //
        Hashtable                   attrs = new Hashtable();
        Vector                      order = new Vector();

        attrs.put(X509Principal.C, "AU");
        attrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
        attrs.put(X509Principal.L, "Melbourne");
        attrs.put(X509Principal.ST, "Victoria");
        attrs.put(X509Principal.EmailAddress, "feedback-crypto@bouncycastle.org");

        order.addElement(X509Principal.C);
        order.addElement(X509Principal.O);
        order.addElement(X509Principal.L);
        order.addElement(X509Principal.ST);
        order.addElement(X509Principal.EmailAddress);

        //
        // extensions
        //

        //
        // create the certificate.
        //
        X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(new X509Principal(order, attrs));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(new X509Principal(order, attrs));
        certGen.setPublicKey(pubKey);
        certGen.setSignatureAlgorithm("MD5WithRSAEncryption");

        Certificate[]   chain = new Certificate[1];

        try
        {
            X509Certificate cert = certGen.generate(privKey);

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
            CertificateFactory      fact = CertificateFactory.getInstance("X.509", "BC");

            cert = (X509Certificate)fact.generateCertificate(bIn);

            chain[0] = cert;
        }
        catch (Exception e)
        {
            fail("error generating cert - " + e.toString());
        }

        store.setKeyEntry("private", privKey, passwd, chain);

        //
        // write out and read back store
        //
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();

        store.store(bOut, passwd);

        ByteArrayInputStream    bIn = new ByteArrayInputStream(bOut.toByteArray());

        //
        // start with a new key store
        //
        store = KeyStore.getInstance(storeName, "BC");

        store.load(bIn, passwd);

        //
        // verify public key
        //
        privKey = (RSAPrivateKey)store.getKey("private", passwd);

        if (!privKey.getModulus().equals(modulus))
        {
            fail("private key modulus wrong");
        }
        else if (!privKey.getPrivateExponent().equals(privateExponent))
        {
            fail("private key exponent wrong");
        }

        //
        // verify certificate
        //
        Certificate cert = store.getCertificateChain("private")[0];

        cert.verify(pubKey);
    }

    public String getName()
    {
        return "KeyStore";
    }

    public void performTest()
        throws Exception
    {
        keyStoreTest("BKS");
        keyStoreTest("UBER");
        ecStoreTest("BKS");
        oldStoreTest();
        v1RejectedByDefaultTest();
        checkOversizedEntryRejected();
        checkLargeEntryStreamed();
        checkStoreMacKeyStrength();
        checkVersion1StoreMigrates();
        checkTamperedVersion1StoreRefused();
    }

    // CVE-2026-59651: upstream faf5daa6e's switch; 1.46 reads it as a system property only (no
    // util.Properties, so no thread override), so the tests set and restore the system property.

    private static final String BKS_ENABLE_V1 = "org.bouncycastle.bks.enable_v1";

    // sets the switch to value, or clears it for null; returns the previous value
    private static String setEnableV1(String value)
    {
        String previous = System.getProperty(BKS_ENABLE_V1);

        if (value == null)
        {
            System.clearProperty(BKS_ENABLE_V1);
        }
        else
        {
            System.setProperty(BKS_ENABLE_V1, value);
        }

        return previous;
    }

    private void v1RejectedByDefaultTest()
        throws Exception
    {
        String previous = setEnableV1(null);
        try
        {
            KeyStore ks = KeyStore.getInstance("BKS", "BC");

            ks.load(new ByteArrayInputStream(v1BKS), oldStorePass);

            fail("default BKS loaded a version 1 store without " + BKS_ENABLE_V1);
        }
        catch (IOException e)
        {
            if (!e.getMessage().startsWith("BKS version 1 keystore not supported"))
            {
                fail("unexpected exception: " + e.getMessage());
            }
        }
        finally
        {
            setEnableV1(previous);
        }
    }

    // upstream's BKS and UBER parts (1.46 has no BKS-V1 type); v1BKS needs the switch, as upstream's harness sets it
    private void oldStoreTest()
        throws Exception
    {
        String previous = setEnableV1("true");
        try
        {
            checkStore(KeyStore.getInstance("BKS", "BC"), v1BKS);
        }
        finally
        {
            setEnableV1(previous);
        }
        checkStore(KeyStore.getInstance("BKS", "BC"), v2BKS);
        checkStore(KeyStore.getInstance("UBER", "BC"), v1UBER);
        checkStore(KeyStore.getInstance("UBER", "BC"), v2UBER);
    }

    private void checkStore(KeyStore ks, byte[] data)
        throws Exception
    {
        ks.load(new ByteArrayInputStream(data), oldStorePass);

        if (!ks.containsAlias("android"))
        {
            fail("cannot find alias");
        }

        Key key = ks.getKey("android", oldStorePass);
        if (key == null)
        {
            fail("cannot find key");
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        ks.store(bOut, oldStorePass);
    }

    // CVE-2018-5382: BKS version 0/1 stores key their HMAC-SHA1 integrity MAC with getMacSize() = 20 bits
    // (a 2-byte key); BC 1.47's version 2 store asks for getMacSize() * 8 = 160 bits.

    private static final byte[] storeSecret = Hex.decode("000102030405060708090a0b0c0d0e0f");

    private byte[] createSecretEntryStore(char[] password)
        throws Exception
    {
        KeyStore store = KeyStore.getInstance("BKS", "BC");

        store.load(null, null);
        store.setKeyEntry("trust", storeSecret, null);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        store.store(bOut, password);

        return bOut.toByteArray();
    }

    private static int readStoreVersion(byte[] store)
        throws IOException
    {
        return new DataInputStream(new ByteArrayInputStream(store)).readInt();
    }

    private static byte[] readStoreMac(byte[] store)
    {
        byte[] mac = new byte[20];

        System.arraycopy(store, store.length - mac.length, mac, 0, mac.length);

        return mac;
    }

    // the HMAC-SHA1 BKS computes over a store's entries, with a PKCS#12 PBE MAC key of macKeyBits bits
    private static byte[] calculateStoreMac(byte[] store, char[] password, int macKeyBits)
        throws IOException
    {
        DataInputStream dIn = new DataInputStream(new ByteArrayInputStream(store));

        dIn.readInt();                                  // store version

        byte[] salt = new byte[dIn.readInt()];

        dIn.readFully(salt);

        int iterationCount = dIn.readInt();
        int bodyStart = 4 + 4 + salt.length + 4;
        int bodyLength = store.length - 20 - bodyStart;

        PBEParametersGenerator pbeGen = new PKCS12ParametersGenerator(new SHA1Digest());

        pbeGen.init(PBEParametersGenerator.PKCS12PasswordToBytes(password), salt, iterationCount);

        HMac hMac = new HMac(new SHA1Digest());

        hMac.init(pbeGen.generateDerivedMacParameters(macKeyBits));
        hMac.update(store, bodyStart, bodyLength);

        byte[] mac = new byte[hMac.getMacSize()];

        hMac.doFinal(mac, 0);

        return mac;
    }

    // a copy of store with the given version field and its MAC recomputed with a macKeyBits key
    private static byte[] rewriteStore(byte[] store, int version, char[] password, int macKeyBits)
        throws IOException
    {
        byte[] copy = Arrays.clone(store);

        copy[0] = (byte)(version >>> 24);
        copy[1] = (byte)(version >>> 16);
        copy[2] = (byte)(version >>> 8);
        copy[3] = (byte)version;

        byte[] mac = calculateStoreMac(copy, password, macKeyBits);

        System.arraycopy(mac, 0, copy, copy.length - mac.length, mac.length);

        return copy;
    }

    private void checkStoreMacKeyStrength()
        throws Exception
    {
        byte[] store = createSecretEntryStore(passwd);

        if (!Arrays.areEqual(readStoreMac(store), calculateStoreMac(store, passwd, 160)))
        {
            fail("BKS store MAC is not keyed with 160 bits");
        }
        if (readStoreVersion(store) != 2)
        {
            fail("BKS store written as version " + readStoreVersion(store) + ", not 2");
        }

        // a version 2 store whose MAC was made with the legacy 2-byte key fails its integrity check
        byte[] weakMac = rewriteStore(store, 2, passwd, 20);
        KeyStore ks = KeyStore.getInstance("BKS", "BC");

        try
        {
            ks.load(new ByteArrayInputStream(weakMac), passwd);
            fail("version 2 BKS store with a 16-bit-key MAC accepted");
        }
        catch (IOException e)
        {
            if (!"KeyStore integrity check failed.".equals(e.getMessage()))
            {
                fail("unexpected exception: " + e.getMessage());
            }
        }
    }

    // migration: with the switch on, a version 1 store (as unpatched 1.46 writes it, and upstream's v1BKS) loads
    // and store() rewrites it as version 2 with a 160-bit MAC key; with the switch off again it loads
    private void checkVersion1StoreMigrates()
        throws Exception
    {
        checkVersion1StoreMigrates(rewriteStore(createSecretEntryStore(passwd), 1, passwd, 20), passwd, "trust");
        checkVersion1StoreMigrates(v1BKS, oldStorePass, "android");
    }

    private void checkVersion1StoreMigrates(byte[] v1Store, char[] password, String alias)
        throws Exception
    {
        String previous = setEnableV1("true");
        try
        {
            KeyStore ks = KeyStore.getInstance("BKS", "BC");

            ks.load(new ByteArrayInputStream(v1Store), password);

            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            ks.store(bOut, password);

            byte[] migrated = bOut.toByteArray();

            if (readStoreVersion(migrated) != 2)
            {
                fail("re-saved version 1 BKS store written as version " + readStoreVersion(migrated) + ", not 2");
            }
            if (!Arrays.areEqual(readStoreMac(migrated), calculateStoreMac(migrated, password, 160)))
            {
                fail("re-saved version 1 BKS store MAC is not keyed with 160 bits");
            }

            setEnableV1(null);

            ks = KeyStore.getInstance("BKS", "BC");
            ks.load(new ByteArrayInputStream(migrated), password);

            if (ks.size() != 1 || !ks.isKeyEntry(alias))
            {
                fail("re-saved version 1 BKS store lost its entry");
            }
        }
        finally
        {
            setEnableV1(previous);
        }
    }

    // a version 1 store with an altered entry and its MAC recomputed with the 2-byte key: accepted
    // before, refused by default now, whether or not a password is given
    private void checkTamperedVersion1StoreRefused()
        throws Exception
    {
        byte[] v1Store = rewriteStore(createSecretEntryStore(passwd), 1, passwd, 20);
        byte[] trust = new byte[] { 0, 5, 't', 'r', 'u', 's', 't' };
        int at = -1;

        for (int i = 0; i + trust.length <= v1Store.length; i++)
        {
            byte[] window = new byte[trust.length];

            System.arraycopy(v1Store, i, window, 0, trust.length);
            if (Arrays.areEqual(window, trust))
            {
                if (at >= 0)
                {
                    fail("alias found twice in test store");
                }
                at = i;
            }
        }
        if (at < 0)
        {
            fail("alias not found in test store");
        }

        byte[] altered = Arrays.clone(v1Store);

        System.arraycopy(new byte[] { 'r', 'o', 'g', 'u', 'e' }, 0, altered, at + 2, 5);

        byte[] tampered = rewriteStore(altered, 1, passwd, 20);
        char[][] passwords = { passwd, null };

        String previous = setEnableV1(null);
        try
        {
            for (int p = 0; p != passwords.length; p++)
            {
                KeyStore ks = KeyStore.getInstance("BKS", "BC");

                try
                {
                    ks.load(new ByteArrayInputStream(tampered), passwords[p]);
                    fail("tampered version 1 BKS store accepted" + (ks.containsAlias("rogue") ? ", with its altered entry" : ""));
                }
                catch (IOException e)
                {
                    if (!e.getMessage().startsWith("BKS version 1 keystore not supported"))
                    {
                        fail("unexpected exception: " + e.getMessage());
                    }
                }
            }
        }
        finally
        {
            setEnableV1(previous);
        }
    }

    // CVE-2026-12185: upstream 7bbd7fe5f's two tests

    /*
     * An entry whose declared length genuinely exceeds the read buffer (and whose bytes are
     * actually present) must still load: the incremental read has to consume exactly the
     * declared number of bytes, otherwise the trailing store MAC would misalign and the load
     * would fail. Confirms the bounded-buffer hardening did not turn into a hard size cap.
     */
    private void checkLargeEntryStreamed()
        throws Exception
    {
        int bigLength = (2 * 1024 * 1024) + 1000;   // just over the 2 MiB read buffer

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(2);                            // store version
        dos.writeInt(20);                           // salt length
        dos.write(new byte[20]);                    // salt
        dos.writeInt(1024);                         // iteration count
        dos.write(3);                               // entry type = SECRET
        dos.writeUTF("big");                        // alias
        dos.writeLong(System.currentTimeMillis());  // creation date
        dos.writeInt(0);                            // chain length
        dos.writeInt(bigLength);                    // blob length, > read buffer
        dos.write(new byte[bigLength]);             // the blob bytes really are present
        dos.write(0);                               // NULL entry terminator
        dos.write(new byte[20]);                    // store MAC (not checked for null password)

        KeyStore ks = KeyStore.getInstance("BKS", "BC");
        ks.load(new ByteArrayInputStream(baos.toByteArray()), null);

        if (!ks.containsAlias("big"))
        {
            fail("large entry not loaded");
        }
        if (ks.size() != 1)
        {
            fail("unexpected entry count");
        }
    }

    /*
     * A crafted BKS/UBER stream declaring an enormous length-prefixed allocation must be
     * rejected with an IOException rather than driving an unbounded array allocation /
     * OutOfMemoryError before the integrity MAC is checked. The poison is reached regardless of
     * the password supplied, since loadStore() runs ahead of the MAC comparison.
     */
    private void checkOversizedEntryRejected()
        throws Exception
    {
        char[][] passwords = {null, new char[0], "test".toCharArray()};

        // BKS: a KEY entry with an Integer.MAX_VALUE certificate chain length.
        ByteArrayOutputStream chainPoison = new ByteArrayOutputStream();
        DataOutputStream c = new DataOutputStream(chainPoison);
        c.writeInt(2);                              // store version
        c.writeInt(20);                             // salt length
        c.write(new byte[20]);                      // salt
        c.writeInt(1024);                           // iteration count
        c.write(2);                                 // entry type = KEY
        c.writeUTF("evil");                         // alias
        c.writeLong(System.currentTimeMillis());    // creation date
        c.writeInt(Integer.MAX_VALUE);              // poison chain length

        // BKS: a SECRET entry (chain length 0) with an Integer.MAX_VALUE blob length.
        ByteArrayOutputStream blobPoison = new ByteArrayOutputStream();
        DataOutputStream b = new DataOutputStream(blobPoison);
        b.writeInt(2);
        b.writeInt(20);
        b.write(new byte[20]);
        b.writeInt(1024);
        b.write(3);                                 // entry type = SECRET
        b.writeUTF("evil");
        b.writeLong(System.currentTimeMillis());
        b.writeInt(0);                              // chain length
        b.writeInt(Integer.MAX_VALUE);              // poison blob length

        // BKS / UBER: an Integer.MAX_VALUE store salt length, read before any cipher is set up.
        ByteArrayOutputStream saltPoison = new ByteArrayOutputStream();
        DataOutputStream s = new DataOutputStream(saltPoison);
        s.writeInt(2);
        s.writeInt(Integer.MAX_VALUE);              // poison salt length

        for (int p = 0; p != passwords.length; p++)
        {
            loadShouldRejectNotOOM("BKS", chainPoison.toByteArray(), passwords[p]);
            loadShouldRejectNotOOM("BKS", blobPoison.toByteArray(), passwords[p]);
            loadShouldRejectNotOOM("BKS", saltPoison.toByteArray(), passwords[p]);
            loadShouldRejectNotOOM("UBER", saltPoison.toByteArray(), passwords[p]);
        }
    }

    private void loadShouldRejectNotOOM(String type, byte[] poison, char[] password)
        throws Exception
    {
        KeyStore ks = KeyStore.getInstance(type, "BC");
        try
        {
            ks.load(new ByteArrayInputStream(poison), password);
            fail("oversized " + type + " allocation not rejected");
        }
        catch (IOException e)
        {
            // expected - the length is rejected before the array is allocated and read
        }
        catch (OutOfMemoryError e)
        {
            fail("oversized " + type + " allocation caused OutOfMemoryError");
        }
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new KeyStoreTest());
    }
}
