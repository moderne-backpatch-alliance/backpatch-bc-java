package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Exception;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1RelativeOID;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Object identifier and relative OID contents are limited to 4096 octets, on the parse path, from
 * contents octets and from the string forms.
 */
public class OIDLengthLimitTest
    extends SimpleTest
{
    public String getName()
    {
        return "OIDLengthLimit";
    }

    public void performTest()
        throws Exception
    {
        // 4096 contents octets: "1.2" followed by 4095 arcs of 1
        ASN1ObjectIdentifier atLimit = (ASN1ObjectIdentifier)new ASN1InputStream(oidEncoding(4096)).readObject();
        isEquals("4096 octets", 3 + 2 * 4095, atLimit.getId().length());

        try
        {
            new ASN1InputStream(oidEncoding(4097)).readObject();
            fail("OID with 4097 contents octets parsed");
        }
        catch (ASN1Exception e)
        {
            isEquals("exceeded OID contents length limit", e.getCause().getMessage());
        }

        try
        {
            ASN1ObjectIdentifier.fromContents(oidContents(4097));
            fail("OID with 4097 contents octets created");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("exceeded OID contents length limit", e.getMessage());
        }

        new ASN1ObjectIdentifier(oidString(4095));
        try
        {
            new ASN1ObjectIdentifier(oidString(4096));
            fail("OID string with 4097 contents octets accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("exceeded OID contents length limit", e.getMessage());
        }

        try
        {
            new ASN1ObjectIdentifier("1.2." + digits(20000));
            fail("over-long OID string accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("exceeded OID contents length limit", e.getMessage());
        }

        try
        {
            new ASN1ObjectIdentifier("1.2").branch("1" + arcs(4095));
            fail("OID branch with 4097 contents octets accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("exceeded OID contents length limit", e.getMessage());
        }

        // relative OIDs: the same limit
        byte[] relContents = new byte[4097];
        for (int i = 0; i != relContents.length; i++)
        {
            relContents[i] = 1;
        }
        try
        {
            ASN1RelativeOID.fromContents(relContents);
            fail("relative OID with 4097 contents octets created");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("exceeded relative OID contents length limit", e.getMessage());
        }

        new ASN1RelativeOID("1" + arcs(4095));
        try
        {
            new ASN1RelativeOID("1" + arcs(4096));
            fail("relative OID string with 4097 contents octets accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("exceeded relative OID contents length limit", e.getMessage());
        }
    }

    private static byte[] oidContents(int length)
    {
        byte[] contents = new byte[length];
        contents[0] = 0x2A;     // 1.2
        for (int i = 1; i != length; i++)
        {
            contents[i] = 1;
        }
        return contents;
    }

    private static byte[] oidEncoding(int length)
    {
        byte[] contents = oidContents(length);
        byte[] enc = new byte[4 + length];
        enc[0] = 0x06;
        enc[1] = (byte)0x82;
        enc[2] = (byte)(length >> 8);
        enc[3] = (byte)length;
        System.arraycopy(contents, 0, enc, 4, length);
        return enc;
    }

    private static String arcs(int count)
    {
        StringBuffer sb = new StringBuffer(2 * count);
        for (int i = 0; i != count; i++)
        {
            sb.append(".1");
        }
        return sb.toString();
    }

    private static String oidString(int arcCount)
    {
        return "1.2" + arcs(arcCount);
    }

    private static String digits(int count)
    {
        StringBuffer sb = new StringBuffer(count);
        for (int i = 0; i != count; i++)
        {
            sb.append('7');
        }
        return sb.toString();
    }

    public static void main(String[] args)
    {
        runTest(new OIDLengthLimitTest());
    }
}
