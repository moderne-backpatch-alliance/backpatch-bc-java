package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.util.test.SimpleTest;

/**
 * RDN value escaping in IETFUtils.valueToString must run in linear time (a million commas in well under 5 s;
 * the insert-based escaping takes tens of seconds).
 */
public class RDNEscapeTest
    extends SimpleTest
{
    private static final int LARGE = 1000000;
    private static final long TIME_LIMIT_MS = 5000;

    public String getName()
    {
        return "RDNEscape";
    }

    public void performTest()
        throws Exception
    {
        long ietfUtils = timeIETFUtilsLargeValue();
        isTrue("escaping " + LARGE + " commas took " + ietfUtils + " ms (IETFUtils)", ietfUtils < TIME_LIMIT_MS);
    }

    private long timeIETFUtilsLargeValue()
    {
        DERUTF8String value = new DERUTF8String(commas(LARGE));

        long start = System.currentTimeMillis();
        String s = IETFUtils.valueToString(value);
        long elapsed = System.currentTimeMillis() - start;

        isEquals("IETFUtils escaped length", 2 * LARGE, s.length());
        return elapsed;
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

    public static void main(String[] args)
    {
        runTest(new RDNEscapeTest());
    }
}
