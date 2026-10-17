package org.bouncycastle.jce.provider.test;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Exception;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.x509.X509AttributeCertificate;
import org.bouncycastle.x509.X509CertificatePair;
import org.bouncycastle.x509.X509StreamParser;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Random;
import java.util.Vector;

public class X509StreamParserTest
    extends SimpleTest
{
    byte[]  attrCert = Base64.decode(
        "MIIHQDCCBqkCAQEwgZChgY2kgYowgYcxHDAaBgkqhkiG9w0BCQEWDW1sb3JjaEB2"
      + "dC5lZHUxHjAcBgNVBAMTFU1hcmt1cyBMb3JjaCAobWxvcmNoKTEbMBkGA1UECxMS"
      + "VmlyZ2luaWEgVGVjaCBVc2VyMRAwDgYDVQQLEwdDbGFzcyAyMQswCQYDVQQKEwJ2"
      + "dDELMAkGA1UEBhMCVVMwgYmkgYYwgYMxGzAZBgkqhkiG9w0BCQEWDHNzaGFoQHZ0"
      + "LmVkdTEbMBkGA1UEAxMSU3VtaXQgU2hhaCAoc3NoYWgpMRswGQYDVQQLExJWaXJn"
      + "aW5pYSBUZWNoIFVzZXIxEDAOBgNVBAsTB0NsYXNzIDExCzAJBgNVBAoTAnZ0MQsw"
      + "CQYDVQQGEwJVUzANBgkqhkiG9w0BAQQFAAIBBTAiGA8yMDAzMDcxODE2MDgwMloY"
      + "DzIwMDMwNzI1MTYwODAyWjCCBU0wggVJBgorBgEEAbRoCAEBMYIFORaCBTU8UnVs"
      + "ZSBSdWxlSWQ9IkZpbGUtUHJpdmlsZWdlLVJ1bGUiIEVmZmVjdD0iUGVybWl0Ij4K"
      + "IDxUYXJnZXQ+CiAgPFN1YmplY3RzPgogICA8U3ViamVjdD4KICAgIDxTdWJqZWN0"
      + "TWF0Y2ggTWF0Y2hJZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5j"
      + "dGlvbjpzdHJpbmctZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlw"
      + "ZT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjc3RyaW5nIj4KICAg"
      + "ICAgIENOPU1hcmt1cyBMb3JjaDwvQXR0cmlidXRlVmFsdWU+CiAgICAgPFN1Ympl"
      + "Y3RBdHRyaWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFt"
      + "ZXM6dGM6eGFjbWw6MS4wOnN1YmplY3Q6c3ViamVjdC1pZCIgRGF0YVR5cGU9Imh0"
      + "dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hI3N0cmluZyIgLz4gCiAgICA8"
      + "L1N1YmplY3RNYXRjaD4KICAgPC9TdWJqZWN0PgogIDwvU3ViamVjdHM+CiAgPFJl"
      + "c291cmNlcz4KICAgPFJlc291cmNlPgogICAgPFJlc291cmNlTWF0Y2ggTWF0Y2hJ"
      + "ZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5jdGlvbjpzdHJpbmct"
      + "ZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlwZT0iaHR0cDovL3d3"
      + "dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIj4KICAgICAgaHR0cDovL3p1"
      + "bmkuY3MudnQuZWR1PC9BdHRyaWJ1dGVWYWx1ZT4KICAgICA8UmVzb3VyY2VBdHRy"
      + "aWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6"
      + "eGFjbWw6MS4wOnJlc291cmNlOnJlc291cmNlLWlkIiBEYXRhVHlwZT0iaHR0cDov"
      + "L3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIiAvPiAKICAgIDwvUmVz"
      + "b3VyY2VNYXRjaD4KICAgPC9SZXNvdXJjZT4KICA8L1Jlc291cmNlcz4KICA8QWN0"
      + "aW9ucz4KICAgPEFjdGlvbj4KICAgIDxBY3Rpb25NYXRjaCBNYXRjaElkPSJ1cm46"
      + "b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmZ1bmN0aW9uOnN0cmluZy1lcXVhbCI+"
      + "CiAgICAgPEF0dHJpYnV0ZVZhbHVlIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9y"
      + "Zy8yMDAxL1hNTFNjaGVtYSNzdHJpbmciPgpEZWxlZ2F0ZSBBY2Nlc3MgICAgIDwv"
      + "QXR0cmlidXRlVmFsdWU+CgkgIDxBY3Rpb25BdHRyaWJ1dGVEZXNpZ25hdG9yIEF0"
      + "dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmFjdGlvbjph"
      + "Y3Rpb24taWQiIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNj"
      + "aGVtYSNzdHJpbmciIC8+IAogICAgPC9BY3Rpb25NYXRjaD4KICAgPC9BY3Rpb24+"
      + "CiAgPC9BY3Rpb25zPgogPC9UYXJnZXQ+CjwvUnVsZT4KMA0GCSqGSIb3DQEBBAUA"
      + "A4GBAGiJSM48XsY90HlYxGmGVSmNR6ZW2As+bot3KAfiCIkUIOAqhcphBS23egTr"
      + "6asYwy151HshbPNYz+Cgeqs45KkVzh7bL/0e1r8sDVIaaGIkjHK3CqBABnfSayr3"
      + "Rd1yBoDdEv8Qb+3eEPH6ab9021AsLEnJ6LWTmybbOpMNZ3tv");

    // test written for the backpatch (CVE-2025-8885): OID contents are limited to 4096 octets, as upstream
    private void testOidContentsLimit()
        throws Exception
    {
        DERObjectIdentifier oid = (DERObjectIdentifier)new ASN1InputStream(oidEncoding(4096)).readObject();
        if (!oid.getId().startsWith("1.2.1.1."))
        {
            fail("4096 octet OID parsed wrongly");
        }

        try
        {
            new ASN1InputStream(oidEncoding(4097)).readObject();
            fail("4097 octet OID accepted");
        }
        catch (IOException e)
        {
            // expected
        }

        StringBuffer id = new StringBuffer("1.2");
        while (id.length() < 4096 * 4 + 1)
        {
            id.append(".1");
        }
        try
        {
            new ASN1ObjectIdentifier(id.toString() + "1");
            fail("over-long OID string accepted");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    // OBJECT IDENTIFIER 1.2.1.1... with the given number of contents octets
    private static byte[] oidEncoding(int contentsLength)
    {
        byte[] enc = new byte[contentsLength + 4];
        enc[0] = 0x06;
        enc[1] = (byte)0x82;
        enc[2] = (byte)(contentsLength >> 8);
        enc[3] = (byte)contentsLength;
        enc[4] = 0x2a;
        for (int i = 5; i != enc.length; i++)
        {
            enc[i] = 0x01;
        }
        return enc;
    }

    // CVE-2026-14682: upstream 37094e504's DefiniteLengthAllocationTest, in the provider tests (1.46 ships no asn1 tests)
    /**
     * A large declared length must not be requested (and therefore allocated) in a single up-front
     * read: the eager {@code new byte[length]} asked the stream for the whole declared length at
     * once, whereas the guard reads into a bounded, incrementally grown buffer.
     */
    private void testDeclaredLengthNotAllocatedUpFront()
        throws IOException
    {
        int declaredLength = 1 << 20;   // 1 MiB - comfortably past the bounded working buffer

        // OCTET STRING (tag 0x04), long-form length 0x100000, followed by a full body.
        byte[] input = new byte[5 + declaredLength];
        input[0] = (byte)0x04;
        input[1] = (byte)0x83;          // long form, 3 length octets
        input[2] = (byte)0x10;
        input[3] = (byte)0x00;
        input[4] = (byte)0x00;

        RecordingStream in = new RecordingStream(input);
        ASN1OctetString octets = (ASN1OctetString)new ASN1InputStream(in).readObject();

        if (octets.getOctets().length != declaredLength)
        {
            fail("octet string did not materialize to the declared length");
        }
        if (!(in.firstBulkReadLength >= 0 && in.firstBulkReadLength < declaredLength))
        {
            fail("first bulk read requested the full declared length (" + in.firstBulkReadLength + ")");
        }
    }

    /**
     * A definite-length object whose stream ends early still fails with the exact truncation
     * message the eager read produced (the message text is asserted elsewhere in the suite).
     */
    private void testTruncatedObjectReportsExpectedMessage()
    {
        int declaredLength = 1 << 20;
        int bodySupplied = 10;

        byte[] input = new byte[5 + bodySupplied];
        input[0] = (byte)0x04;
        input[1] = (byte)0x83;
        input[2] = (byte)0x10;
        input[3] = (byte)0x00;
        input[4] = (byte)0x00;

        try
        {
            new ASN1InputStream(new RecordingStream(input)).readObject();
            fail("no exception on truncated definite-length object");
        }
        catch (EOFException e)
        {
            String expected = "DEF length " + declaredLength + " object truncated by " + (declaredLength - bodySupplied);
            if (!expected.equals(e.getMessage()))
            {
                fail("unexpected truncation message: " + e.getMessage());
            }
        }
        catch (IOException e)
        {
            fail("unexpected exception: " + e);
        }
    }

    /**
     * A generic InputStream (so the stream limit takes its Integer.MAX_VALUE fallback) that
     * records the size of the first bulk read(byte[], int, int) request.
     */
    private static final class RecordingStream
        extends InputStream
    {
        private final byte[] data;
        private int pos = 0;
        int firstBulkReadLength = -1;

        RecordingStream(byte[] data)
        {
            this.data = data;
        }

        public int read()
        {
            return pos < data.length ? (data[pos++] & 0xFF) : -1;
        }

        public int read(byte[] buf, int off, int len)
        {
            if (firstBulkReadLength < 0)
            {
                firstBulkReadLength = len;
            }
            if (pos >= data.length)
            {
                return -1;
            }
            int n = Math.min(len, data.length - pos);
            System.arraycopy(data, pos, buf, off, n);
            pos += n;
            return n;
        }
    }

    // test written for the backpatch (CVE-2026-58059): RDN values escape in linear time through X500Name
    // (IETFUtils) and X509Name, with the same output as the old insert-based escaping
    private void testRDNEscapeLinear()
    {
        String[] fixed = { "", "a", ",", "\\#abc", "#abc", "a,b+c=d<e>f;g\"h\\i", ",,,", "\\", "\\#,", " lead", "trail " };
        Random rand = new Random(46);
        String chars = "ab ,+=<>;\"\\#";
        for (int i = 0; i != 20000 + fixed.length; i++)
        {
            String v;
            if (i < fixed.length)
            {
                v = fixed[i];
            }
            else
            {
                char[] cs = new char[rand.nextInt(8)];
                for (int j = 0; j != cs.length; j++)
                {
                    cs[j] = chars.charAt(rand.nextInt(chars.length()));
                }
                v = new String(cs);
            }

            String x509 = x509NameString(v);
            if (!x509.equals("CN=" + oldEscape(v)))
            {
                fail("X509Name escaping changed for [" + v + "]: " + x509);
            }
            String x500 = new X500Name(new RDN[]{ new RDN(BCStyle.CN, new DERUTF8String(v)) }).toString();
            if (!x500.equals("CN=" + oldEscape(v.startsWith("#") ? "\\" + v : v)))
            {
                fail("X500Name escaping changed for [" + v + "]: " + x500);
            }
        }

        char[] commas = new char[1000000];
        for (int i = 0; i != commas.length; i++)
        {
            commas[i] = ',';
        }
        String big = new String(commas);

        long start = System.currentTimeMillis();
        int x509Len = x509NameString(big).length();
        long x509Time = System.currentTimeMillis() - start;

        start = System.currentTimeMillis();
        int x500Len = new X500Name(new RDN[]{ new RDN(BCStyle.CN, new DERUTF8String(big)) }).toString().length();
        long x500Time = System.currentTimeMillis() - start;

        if (x509Len != 3 + 2 * commas.length || x500Len != 3 + 2 * commas.length)
        {
            fail("1,000,000 commas escaped wrongly");
        }
        if (x509Time > 5000 || x500Time > 5000)
        {
            fail("1,000,000 commas took " + x509Time + " ms (X509Name) and " + x500Time + " ms (X500Name)");
        }
    }

    private static String x509NameString(String value)
    {
        Vector oids = new Vector();
        Vector values = new Vector();
        oids.addElement(X509Name.CN);
        values.addElement(value);
        return new X509Name(oids, values).toString();
    }

    // the escaping of the baseline's X509Name.appendValue and IETFUtils.valueToString, applied to the whole value
    private static String oldEscape(String value)
    {
        StringBuffer buf = new StringBuffer(value);
        int index = 0;
        int end = buf.length();

        if (value.length() >= 2 && value.charAt(0) == '\\' && value.charAt(1) == '#')
        {
            index += 2;
        }

        while (index != end)
        {
            char c = buf.charAt(index);
            if (c == ',' || c == '"' || c == '\\' || c == '+' || c == '=' || c == '<' || c == '>' || c == ';')
            {
                buf.insert(index, "\\");
                index++;
                end++;
            }

            index++;
        }

        return buf.toString();
    }

    // CVE-2026-13506: upstream's three tests (02527424e, 77454da9b) with the nested input built here instead of read
    // from bc-test-data (1300 levels, as upstream's nested_seq.der and nested_seq_indef.ber), plus the property
    // and default-boundary tests written for the backpatch (as on 1.78.1)
    private void testHeavilyDLNestedSequence()
        throws Exception
    {
        try
        {
            new ASN1InputStream(dlNestedSequence(1300)).readObject();
            fail("no exception");
        }
        catch (ASN1Exception e)
        {
            if (!"maximum nested construction level reached".equals(e.getMessage()))
            {
                fail("wrong message: " + e.getMessage());
            }
        }
    }

    private void testHeavilyBERNestedSequence()
        throws Exception
    {
        try
        {
            new ASN1InputStream(berNestedSequence(1300)).readObject();
            fail("no exception");
        }
        catch (ASN1Exception e)
        {
            if (!"maximum nested construction level reached".equals(e.getMessage()))
            {
                fail("wrong message: " + e.getMessage());
            }
        }
    }

    private void testHeavilyLazyNestedSequence()
        throws Exception
    {
        // Deeply nested SEQUENCE { SEQUENCE { ... } }, well past the default max_cons_depth (64)
        // but shallow enough that a whole-tree walk would not itself overflow the Java stack if the
        // guard were absent -- so this proves the guard is enforced, not merely that we crash.
        byte[] der = dlNestedSequence(256);

        // The lazy parse succeeds shallowly (only the outermost level is decoded eagerly).
        DERObject parsed = new ASN1InputStream(der, true).readObject();

        // Forcing the whole tree (hashCode walks every element) must hit the same nested-construction
        // limit the eager path enforces, raising an ASN1Exception rather than a StackOverflowError.
        try
        {
            parsed.hashCode();
            fail("nested construction depth limit not enforced on lazy parse");
        }
        catch (ASN1ParsingException e)
        {
            if (!"maximum nested construction level reached".equals(e.getCause().getMessage()))
            {
                fail("wrong message: " + e.getCause().getMessage());
            }
        }
    }

    private void testDefaultMaxConsDepth()
        throws Exception
    {
        new ASN1InputStream(dlNestedSequence(64)).readObject();
        new ASN1InputStream(dlNestedSequence(64), true).readObject().hashCode();
        new ASN1InputStream(berNestedSequence(64)).readObject();

        byte[][] tooDeep = { dlNestedSequence(65), berNestedSequence(65) };
        for (int i = 0; i != tooDeep.length; i++)
        {
            try
            {
                new ASN1InputStream(tooDeep[i]).readObject();
                fail("default nested construction depth limit not enforced: " + i);
            }
            catch (ASN1Exception e)
            {
                // expected
            }
        }
        try
        {
            new ASN1InputStream(dlNestedSequence(65), true).readObject().hashCode();
            fail("default nested construction depth limit not enforced on lazy parse");
        }
        catch (ASN1ParsingException e)
        {
            // expected
        }
    }

    private void testMaxConsDepthProperty()
        throws Exception
    {
        System.setProperty("org.bouncycastle.asn1.max_cons_depth", "8");
        try
        {
            new ASN1InputStream(dlNestedSequence(8)).readObject();
            new ASN1InputStream(dlNestedSequence(8), true).readObject().hashCode();
            new ASN1InputStream(berNestedSequence(8)).readObject();
            try
            {
                new ASN1InputStream(dlNestedSequence(9)).readObject();
                fail("max_cons_depth 8 not enforced");
            }
            catch (ASN1Exception e)
            {
                // expected
            }
            try
            {
                new ASN1InputStream(berNestedSequence(9)).readObject();
                fail("max_cons_depth 8 not enforced on BER");
            }
            catch (ASN1Exception e)
            {
                // expected
            }
            try
            {
                new ASN1InputStream(dlNestedSequence(9), true).readObject().hashCode();
                fail("max_cons_depth 8 not enforced on lazy parse");
            }
            catch (ASN1ParsingException e)
            {
                // expected
            }
        }
        finally
        {
            System.getProperties().remove("org.bouncycastle.asn1.max_cons_depth");
        }
    }

    // n nested definite-length SEQUENCEs, the innermost holding an INTEGER
    private static byte[] dlNestedSequence(int n)
        throws IOException
    {
        DEREncodable node = new DERInteger(1);
        for (int i = 0; i < n; i++)
        {
            node = new DERSequence(node);
        }
        return node.getDERObject().getEncoded();
    }

    // n nested indefinite-length SEQUENCEs, the innermost holding an INTEGER
    private static byte[] berNestedSequence(int n)
    {
        byte[] enc = new byte[4 * n + 3];
        int pos = 0;
        for (int i = 0; i < n; i++)
        {
            enc[pos++] = 0x30;
            enc[pos++] = (byte)0x80;
        }
        enc[pos++] = 0x02;
        enc[pos++] = 0x01;
        enc[pos++] = 0x01;
        for (int i = 0; i < n; i++)
        {
            enc[pos++] = 0x00;
            enc[pos++] = 0x00;
        }
        return enc;
    }

    public void performTest()
        throws Exception
    {
        testHeavilyDLNestedSequence();
        testHeavilyBERNestedSequence();
        testHeavilyLazyNestedSequence();
        testDefaultMaxConsDepth();
        testMaxConsDepthProperty();
        testRDNEscapeLinear();
        testDeclaredLengthNotAllocatedUpFront();
        testTruncatedObjectReportsExpectedMessage();
        testOidContentsLimit();

        X509StreamParser parser = X509StreamParser.getInstance("Certificate", "BC");

        parser.init(new ByteArrayInputStream(CertPathTest.rootCertBin));
        X509Certificate rootCert = (X509Certificate)parser.read();

        parser = X509StreamParser.getInstance("CRL", "BC");

        parser.init(new ByteArrayInputStream(CertPathTest.rootCrlBin));


        X509CRL rootCrl = (X509CRL)parser.read();

        parser = X509StreamParser.getInstance("AttributeCertificate", "BC");

        parser.init(new ByteArrayInputStream(attrCert));

        X509AttributeCertificate aCert = (X509AttributeCertificate)parser.read();

        ByteArrayOutputStream  bOut = new ByteArrayOutputStream();

        bOut.write(CertPathTest.rootCertBin);
        bOut.write(CertPathTest.interCertBin);
        bOut.write(CertPathTest.finalCertBin);

        parser = X509StreamParser.getInstance("Certificate", "BC");

        parser.init(bOut.toByteArray());

        Collection res = parser.readAll();

        if (res.size() != 3)
        {
            fail("wrong number of certificates found");
        }

        bOut = new ByteArrayOutputStream();

        bOut.write(CertPathTest.rootCrlBin);
        bOut.write(CertPathTest.interCrlBin);

        parser = X509StreamParser.getInstance("CRL", "BC");

        parser.init(bOut.toByteArray());

        res = parser.readAll();

        if (res.size() != 2)
        {
            fail("wrong number of CRLs found");
        }

        bOut = new ByteArrayOutputStream();

        bOut.write(attrCert);
        bOut.write(attrCert);

        parser = X509StreamParser.getInstance("AttributeCertificate", "BC");

        parser.init(bOut.toByteArray());

        res = parser.readAll();

        if (res.size() != 2)
        {
            fail("wrong number of Attribute Certificates found");
        }

        //
        // PEM tests
        //
        parser = X509StreamParser.getInstance("Certificate", "BC");

        parser.init(PEMData.CERTIFICATE_1.getBytes("US-ASCII"));

        res = parser.readAll();

        if (res.size() != 1)
        {
            fail("wrong number of Certificates found");
        }

        parser = X509StreamParser.getInstance("Certificate", "BC");

        parser.init(PEMData.CERTIFICATE_2.getBytes("US-ASCII"));

        res = parser.readAll();

        if (res.size() != 1)
        {
            fail("wrong number of Certificates found");
        }

        parser = X509StreamParser.getInstance("CRL", "BC");

        parser.init(PEMData.CRL_1.getBytes("US-ASCII"));

        res = parser.readAll();

        if (res.size() != 1)
        {
            fail("wrong number of CRLs found");
        }

        parser = X509StreamParser.getInstance("CRL", "BC");

        parser.init(PEMData.CRL_2.getBytes("US-ASCII"));

        res = parser.readAll();

        if (res.size() != 1)
        {
            fail("wrong number of CRLs found");
        }

        parser = X509StreamParser.getInstance("AttributeCertificate", "BC");

        parser.init(PEMData.ATTRIBUTE_CERTIFICATE_1.getBytes("US-ASCII"));

        res = parser.readAll();

        if (res.size() != 1)
        {
            fail("wrong number of Attribute Certificates found");
        }

        parser = X509StreamParser.getInstance("AttributeCertificate", "BC");

        parser.init(PEMData.ATTRIBUTE_CERTIFICATE_2.getBytes("US-ASCII"));

        res = parser.readAll();

        if (res.size() != 1)
        {
            fail("wrong number of Attribute Certificates found");
        }

        ASN1EncodableVector certs = new ASN1EncodableVector();

        certs.add(new ASN1InputStream(CertPathTest.rootCertBin).readObject());
        certs.add(new DERTaggedObject(false, 2, new ASN1InputStream(attrCert).readObject()));

        ASN1EncodableVector crls = new ASN1EncodableVector();

        crls.add(new ASN1InputStream(CertPathTest.rootCrlBin).readObject());

        //
        // cross certificate pairs
        //
        parser = X509StreamParser.getInstance("CertificatePair", "BC");

        parser.init(new X509CertificatePair(rootCert, rootCert).getEncoded());

        res = parser.readAll();

        if (res.size() != 1)
        {
            fail("wrong number of CertificatePairs found");
        }

        //
        // PKCS7
        //
        SignedData sigData = new SignedData(new DERSet(), new ContentInfo(CMSObjectIdentifiers.data, null), new DERSet(certs), new DERSet(crls), new DERSet());

        ContentInfo info = new ContentInfo(CMSObjectIdentifiers.signedData, sigData);

        parser = X509StreamParser.getInstance("Certificate", "BC");

        parser.init(info.getEncoded());

        res = parser.readAll();

        if (res.size() != 1)
        {
            fail("wrong number of Certificates found");
        }

        parser = X509StreamParser.getInstance("CRL", "BC");

        parser.init(info.getEncoded());

        res = parser.readAll();

        if (res.size() != 1)
        {
            fail("wrong number of CRLs found");
        }

        parser = X509StreamParser.getInstance("AttributeCertificate", "BC");

        parser.init(info.getEncoded());

        res = parser.readAll();

        if (res.size() != 1)
        {
            fail("wrong number of Attribute Certificates found");
        }

        // data with no certificates or CRLs

        sigData = new SignedData(new DERSet(), new ContentInfo(CMSObjectIdentifiers.data, null), new DERSet(), new DERSet(), new DERSet());

        info = new ContentInfo(CMSObjectIdentifiers.signedData, sigData);

        parser = X509StreamParser.getInstance("Certificate", "BC");

        parser.init(info.getEncoded());

        res = parser.readAll();

        if (res.size() != 0)
        {
            fail("wrong number of Certificates found - expected 0");
        }

        parser = X509StreamParser.getInstance("CRL", "BC");

        parser.init(info.getEncoded());

        res = parser.readAll();

        if (res.size() != 0)
        {
            fail("wrong number of CRLs found - expected 0");
        }

        parser = X509StreamParser.getInstance("AttributeCertificate", "BC");

        parser.init(info.getEncoded());

        res = parser.readAll();

        if (res.size() != 0)
        {
            fail("wrong number of Attribute Certificates found - expected 0");
        }

        // data with absent certificates and CRLs
        sigData = new SignedData(new DERSet(), new ContentInfo(CMSObjectIdentifiers.data, null), null, null, new DERSet());

        info = new ContentInfo(CMSObjectIdentifiers.signedData, sigData);

        parser = X509StreamParser.getInstance("Certificate", "BC");

        parser.init(info.getEncoded());

        res = parser.readAll();

        if (res.size() != 0)
        {
            fail("wrong number of Certificates found - expected 0");
        }

        parser = X509StreamParser.getInstance("CRL", "BC");

        parser.init(info.getEncoded());

        res = parser.readAll();

        if (res.size() != 0)
        {
            fail("wrong number of CRLs found - expected 0");
        }

        parser = X509StreamParser.getInstance("AttributeCertificate", "BC");

        parser.init(info.getEncoded());

        res = parser.readAll();

        if (res.size() != 0)
        {
            fail("wrong number of Attribute Certificates found - expected 0");
        }
    }

    public String getName()
    {
        return "X509StreamParser";
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new X509StreamParserTest());
    }

}
