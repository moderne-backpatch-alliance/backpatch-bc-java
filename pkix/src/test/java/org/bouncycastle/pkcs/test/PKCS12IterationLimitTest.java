package org.bouncycastle.pkcs.test;

import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;
import org.bouncycastle.pkcs.PKCS12MacCalculatorBuilderProvider;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilderProvider;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilderProvider;

/**
 * Without org.bouncycastle.pkcs12.max_it_count set, a PKCS#12 MAC iteration count above
 * 5,000,000 is refused before the key derivation runs. The MAC value itself is filler.
 */
public class PKCS12IterationLimitTest
    extends TestCase
{
    private static final char[] PASSWORD = "hello world".toCharArray();

    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testJceMacDefaultLimit()
        throws Exception
    {
        checkRejected(new JcePKCS12MacCalculatorBuilderProvider().setProvider("BC"));
    }

    public void testBcMacDefaultLimit()
        throws Exception
    {
        checkRejected(new BcPKCS12MacCalculatorBuilderProvider(BcDefaultDigestProvider.INSTANCE));
    }

    private static void checkRejected(PKCS12MacCalculatorBuilderProvider macProv)
        throws Exception
    {
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(pfxWithIterationCount(5000001));

        try
        {
            pfx.isMacValid(macProv, PASSWORD);
            fail("iteration count above the default limit accepted");
        }
        catch (PKCSException e)
        {
            assertTrue(e.getMessage(), e.getMessage().endsWith("iteration count 5000001 greater than 5000000"));
        }
    }

    static byte[] pfxWithIterationCount(int iterationCount)
        throws Exception
    {
        ContentInfo authSafe = new ContentInfo(PKCSObjectIdentifiers.data,
            new DEROctetString(new DERSequence().getEncoded()));
        DigestInfo mac = new DigestInfo(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE), new byte[20]);

        return new Pfx(authSafe, new MacData(mac, new byte[8], iterationCount)).getEncoded();
    }
}
