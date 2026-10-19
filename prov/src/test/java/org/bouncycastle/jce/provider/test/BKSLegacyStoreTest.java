package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

/**
 * A version 1 BKS store's MAC key is 16 bits, so the default BKS type must refuse such a store unless
 * org.bouncycastle.bks.enable_v1 is set, and a store re-saved with the switch on must load with it off.
 */
public class BKSLegacyStoreTest
    extends TestCase
{
    private static final KeyStoreTest VECTORS = new KeyStoreTest();

    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void tearDown()
    {
        Properties.removeThreadOverride(Properties.BKS_ENABLE_V1);
    }

    public void testTamperedV1StoreRefusedByDefault()
        throws Exception
    {
        byte[] store = VECTORS.v1BKS;
        char[] password = VECTORS.oldStorePass;

        DataInputStream dIn = new DataInputStream(new ByteArrayInputStream(store));
        assertEquals(1, dIn.readInt());
        byte[] salt = new byte[dIn.readInt()];
        dIn.readFully(salt);
        int iterationCount = dIn.readInt();
        int headerLength = 12 + salt.length;
        byte[] body = Arrays.copyOfRange(store, headerLength, store.length - 20);
        byte[] storedMac = Arrays.copyOfRange(store, store.length - 20, store.length);

        // the version 1 MAC key derivation, as BcKeyStoreSpi does it for a version 0/1 store
        PBEParametersGenerator pbeGen = new PKCS12ParametersGenerator(new SHA1Digest());
        pbeGen.init(PBEParametersGenerator.PKCS12PasswordToBytes(password), salt, iterationCount);
        HMac hMac = new HMac(new SHA1Digest());
        CipherParameters macKey = pbeGen.generateDerivedMacParameters(hMac.getMacSize());
        assertEquals(2, ((KeyParameter)macKey).getKey().length);
        assertTrue(Arrays.areEqual(storedMac, mac(hMac, macKey, body)));

        // rename the first entry's alias (type byte, then a writeUTF alias) and re-MAC the altered body
        int aliasLength = ((body[1] & 0xff) << 8) | (body[2] & 0xff);
        byte[] tamperedBody = Arrays.clone(body);
        int last = 3 + aliasLength - 1;
        tamperedBody[last] = (byte)(tamperedBody[last] == 'X' ? 'Y' : 'X');
        String alias = new String(body, 3, aliasLength, "UTF-8");
        String forgedAlias = new String(tamperedBody, 3, aliasLength, "UTF-8");
        byte[] tampered = Arrays.concatenate(Arrays.copyOfRange(store, 0, headerLength), tamperedBody,
            mac(hMac, macKey, tamperedBody));

        Properties.setThreadOverride(Properties.BKS_ENABLE_V1, true);
        KeyStore optedIn = KeyStore.getInstance("BKS", "BC");
        optedIn.load(new ByteArrayInputStream(tampered), password);
        assertTrue(optedIn.containsAlias(forgedAlias));
        assertFalse(optedIn.containsAlias(alias));

        Properties.setThreadOverride(Properties.BKS_ENABLE_V1, false);
        KeyStore ks = KeyStore.getInstance("BKS", "BC");
        try
        {
            ks.load(new ByteArrayInputStream(tampered), password);
            fail("default BKS loaded a tampered version 1 store, alias " + forgedAlias + " present: " + ks.containsAlias(forgedAlias));
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("BKS version 1 keystore not supported"));
        }
    }

    public void testV1StoreMigratesWithSwitchOnOnce()
        throws Exception
    {
        char[] password = VECTORS.oldStorePass;

        Properties.setThreadOverride(Properties.BKS_ENABLE_V1, true);
        KeyStore old = KeyStore.getInstance("BKS", "BC");
        old.load(new ByteArrayInputStream(VECTORS.v1BKS), password);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        old.store(bOut, password);
        byte[] migrated = bOut.toByteArray();
        assertEquals(2, new DataInputStream(new ByteArrayInputStream(migrated)).readInt());

        Properties.setThreadOverride(Properties.BKS_ENABLE_V1, false);
        KeyStore ks = KeyStore.getInstance("BKS", "BC");
        ks.load(new ByteArrayInputStream(migrated), password);

        assertEquals(aliases(old), aliases(ks));
        assertFalse(aliases(ks).isEmpty());
        for (Enumeration en = old.aliases(); en.hasMoreElements();)
        {
            String alias = (String)en.nextElement();
            assertEquals(old.isKeyEntry(alias), ks.isKeyEntry(alias));
            assertEquals(old.getCertificate(alias), ks.getCertificate(alias));
            if (old.isKeyEntry(alias))
            {
                Key key = ks.getKey(alias, password);
                assertNotNull(key);
                assertTrue(Arrays.areEqual(old.getKey(alias, password).getEncoded(), key.getEncoded()));
            }
        }
    }

    private static byte[] mac(HMac hMac, CipherParameters key, byte[] data)
    {
        hMac.init(key);
        hMac.update(data, 0, data.length);
        byte[] out = new byte[hMac.getMacSize()];
        hMac.doFinal(out, 0);
        return out;
    }

    private static Set aliases(KeyStore ks)
        throws Exception
    {
        Set set = new HashSet();
        for (Enumeration en = ks.aliases(); en.hasMoreElements();)
        {
            set.add(en.nextElement());
        }
        return set;
    }
}
