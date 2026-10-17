package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Security;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.PKCS12Util;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Without org.bouncycastle.pkcs12.max_it_count set, a PKCS#12 MAC iteration count above
 * 5,000,000 is refused before the key derivation runs. The MAC value itself is filler.
 */
public class PKCS12IterationLimitTest
    extends SimpleTest
{
    private static final char[] PASSWORD = "hello world".toCharArray();
    private static final String MESSAGE = "iteration count 5000001 greater than 5000000";

    public String getName()
    {
        return "PKCS12IterationLimit";
    }

    public void performTest()
        throws Exception
    {
        byte[] pfx = pfxWithIterationCount(5000001);

        KeyStore store = KeyStore.getInstance("PKCS12", "BC");
        try
        {
            store.load(new ByteArrayInputStream(pfx), PASSWORD);
            fail("keystore accepted an iteration count above the default limit");
        }
        catch (IOException e)
        {
            isTrue("keystore: " + e.getMessage(), e.getMessage().endsWith(MESSAGE));
        }

        try
        {
            PKCS12Util.convertToDefiniteLength(pfx, PASSWORD, "BC");
            fail("PKCS12Util accepted an iteration count above the default limit");
        }
        catch (IOException e)
        {
            isTrue("PKCS12Util: " + e.getMessage(), e.getMessage().indexOf(MESSAGE) >= 0);
        }
    }

    private static byte[] pfxWithIterationCount(int iterationCount)
        throws Exception
    {
        ContentInfo authSafe = new ContentInfo(PKCSObjectIdentifiers.data,
            new DEROctetString(new DERSequence().getEncoded()));
        DigestInfo mac = new DigestInfo(new AlgorithmIdentifier(X509ObjectIdentifiers.id_SHA1, DERNull.INSTANCE), new byte[20]);

        return new Pfx(authSafe, new MacData(mac, new byte[8], iterationCount)).getEncoded();
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PKCS12IterationLimitTest());
    }
}
