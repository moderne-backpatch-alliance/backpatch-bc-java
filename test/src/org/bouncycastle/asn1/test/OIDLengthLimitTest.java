package org.bouncycastle.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Exception;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.test.SimpleTest;

public class OIDLengthLimitTest
    extends SimpleTest
{
    private static final String LIMIT_MESSAGE = "exceeded OID contents length limit";

    private final StringBuffer failures = new StringBuffer();

    public String getName()
    {
        return "OIDLengthLimit";
    }

    public void performTest()
        throws Exception
    {
        ASN1ObjectIdentifier atLimit = (ASN1ObjectIdentifier)new ASN1InputStream(oidEncoding(4096)).readObject();
        if (atLimit.getId().length() != 3 + 2 * 4095)
        {
            fail("4096 contents octets parsed wrongly");
        }
        new ASN1ObjectIdentifier(oidString(4095));

        parse("ASN1InputStream, 4097 octets", new ASN1InputStream(oidEncoding(4097)));
        parse("ASN1InputStream, 4097 octets declared, none present", new ASN1InputStream(headerOnly(4097)));
        streamParse("ASN1StreamParser, 4097 octets", oidEncoding(4097));

        try
        {
            ASN1ObjectIdentifier.getInstance(new DERTaggedObject(false, 0, new DEROctetString(oidContents(4097))), false);
            failures.append(" [implicit tag accepted]");
        }
        catch (IllegalArgumentException e)
        {
            check("implicit tag", e.getMessage());
        }

        create("string, 4097 contents octets", oidString(4096));
        create("string, over 16385 characters", "1.2." + digits(20000));

        try
        {
            new ASN1ObjectIdentifier("1.2").branch("1" + arcs(4095));
            failures.append(" [branch, 4097 contents octets accepted]");
        }
        catch (IllegalArgumentException e)
        {
            check("branch", e.getMessage());
        }

        if (failures.length() != 0)
        {
            fail("not refused:" + failures);
        }
    }

    private void parse(String name, ASN1InputStream in)
        throws Exception
    {
        try
        {
            in.readObject();
            failures.append(" [" + name + " accepted]");
        }
        catch (ASN1Exception e)
        {
            check(name, e.getCause().getMessage());
        }
        catch (IOException e)
        {
            failures.append(" [" + name + ": " + e + "]");
        }
    }

    private void streamParse(String name, byte[] enc)
        throws Exception
    {
        try
        {
            new ASN1StreamParser(enc).readObject();
            failures.append(" [" + name + " accepted]");
        }
        catch (ASN1Exception e)
        {
            check(name, e.getCause().getMessage());
        }
    }

    private void create(String name, String identifier)
    {
        try
        {
            new ASN1ObjectIdentifier(identifier);
            failures.append(" [" + name + " accepted]");
        }
        catch (IllegalArgumentException e)
        {
            check(name, e.getMessage());
        }
    }

    private void check(String name, String message)
    {
        if (!LIMIT_MESSAGE.equals(message))
        {
            failures.append(" [" + name + ": " + message + "]");
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

    // not a ByteArrayInputStream, whose size would become the parser's limit
    private static InputStream headerOnly(int length)
    {
        byte[] header = new byte[4];
        System.arraycopy(oidEncoding(length), 0, header, 0, 4);
        return new FilterInputStream(new ByteArrayInputStream(header))
        {
        };
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
