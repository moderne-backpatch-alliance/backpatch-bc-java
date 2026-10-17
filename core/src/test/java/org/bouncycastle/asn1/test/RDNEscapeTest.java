package org.bouncycastle.asn1.test;

import java.lang.reflect.Method;
import java.util.Hashtable;
import java.util.Random;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.util.test.SimpleTest;

/**
 * RDN value escaping in IETFUtils.valueToString and X509Name.toString must run in linear time and,
 * for X509Name, give the same output as the previous insert-based escaping.
 */
public class RDNEscapeTest
    extends SimpleTest
{
    private static final int LARGE = 500000;
    private static final long TIME_LIMIT_MS = 5000;

    public String getName()
    {
        return "RDNEscape";
    }

    public void performTest()
        throws Exception
    {
        testX509NameMatchesInsertEscaping();
        testX509NameLargeValueIsLinear();
        testIETFUtilsLargeValueIsLinear();
    }

    private void testX509NameMatchesInsertEscaping()
        throws Exception
    {
        Method appendValue = X509Name.class.getDeclaredMethod("appendValue",
            new Class[]{ StringBuffer.class, Hashtable.class, ASN1ObjectIdentifier.class, String.class });
        appendValue.setAccessible(true);

        X509Name name = new X509Name("CN=x");
        String[] fixed = new String[]{ "", " ", "   ", "a", "a b", " ab ", "a,b", ",\"\\+=<>;", "\\#", "\\#  x ",
            "\\#ab", "#ab", "  ,  ", "\\", " \\ " };
        for (int i = 0; i != fixed.length; i++)
        {
            checkSame(appendValue, name, fixed[i]);
        }

        char[] alphabet = new char[]{ ' ', ',', '\\', '#', '"', '+', '=', '<', '>', ';', 'a', 'b' };
        Random random = new Random(1);
        for (int i = 0; i != 20000; i++)
        {
            char[] v = new char[random.nextInt(12)];
            for (int j = 0; j != v.length; j++)
            {
                v[j] = alphabet[random.nextInt(alphabet.length)];
            }
            checkSame(appendValue, name, new String(v));
        }
    }

    private void checkSame(Method appendValue, X509Name name, String value)
        throws Exception
    {
        StringBuffer actual = new StringBuffer();
        appendValue.invoke(name, new Object[]{ actual, X509Name.DefaultSymbols, X509Name.CN, value });

        isEquals("escaping of [" + value + "]", insertEscaped(value), actual.toString());
    }

    private void testX509NameLargeValueIsLinear()
    {
        String value = commas(LARGE);
        Vector oids = new Vector();
        Vector values = new Vector();
        oids.addElement(X509Name.CN);
        values.addElement(value);
        X509Name name = new X509Name(oids, values);

        long start = System.currentTimeMillis();
        String s = name.toString();
        long elapsed = System.currentTimeMillis() - start;

        isEquals("X509Name escaped length", 3 + 2 * LARGE, s.length());
        isTrue("X509Name.toString of " + LARGE + " commas took " + elapsed + " ms", elapsed < TIME_LIMIT_MS);
    }

    private void testIETFUtilsLargeValueIsLinear()
    {
        DERUTF8String value = new DERUTF8String(commas(LARGE));

        long start = System.currentTimeMillis();
        String s = IETFUtils.valueToString(value);
        long elapsed = System.currentTimeMillis() - start;

        isEquals("IETFUtils escaped length", 2 * LARGE, s.length());
        isTrue("IETFUtils.valueToString of " + LARGE + " commas took " + elapsed + " ms", elapsed < TIME_LIMIT_MS);
    }

    private static String commas(int n)
    {
        StringBuffer b = new StringBuffer(n);
        for (int i = 0; i != n; i++)
        {
            b.append(',');
        }
        return b.toString();
    }

    /**
     * X509Name's escaping as it was, insert-based, used as the reference for small values.
     */
    private static String insertEscaped(String value)
    {
        StringBuffer buf = new StringBuffer("CN=");

        int start = buf.length();
        buf.append(value);
        int end = buf.length();

        if (value.length() >= 2 && value.charAt(0) == '\\' && value.charAt(1) == '#')
        {
            start += 2;
        }

        while (start < end && buf.charAt(start) == ' ')
        {
            buf.insert(start, "\\");
            start += 2;
            ++end;
        }

        while (--end > start && buf.charAt(end) == ' ')
        {
            buf.insert(end, '\\');
        }

        while (start <= end)
        {
            switch (buf.charAt(start))
            {
            case ',':
            case '"':
            case '\\':
            case '+':
            case '=':
            case '<':
            case '>':
            case ';':
                buf.insert(start, "\\");
                start += 2;
                ++end;
                break;
            default:
                ++start;
                break;
            }
        }

        return buf.toString();
    }

    public static void main(String[] args)
    {
        runTest(new RDNEscapeTest());
    }
}
