package org.bouncycastle.pkcs.util;

import java.math.BigInteger;

import org.bouncycastle.util.Properties;

/**
 * Utility class for PKCS#12 processing.
 */
public class PKCS12Util
{
    private static final BigInteger DEFAULT_MAX_IT_COUNT = BigInteger.valueOf(5000000);

    public static int validateIterationCount(BigInteger ic)
    {
        if (ic.signum() < 0)
        {
            throw new IllegalStateException("negative iteration count found");
        }
        if (ic.bitLength() > 31)
        {
            throw new IllegalStateException("iteration counts >= 2^31 are not suppported");
        }

        BigInteger max = findMaxIterationCount();
        if (max == null)
        {
            max = DEFAULT_MAX_IT_COUNT;
        }

        if (ic.compareTo(max) > 0)
        {
            throw new IllegalStateException("iteration count " + ic + " greater than " + max);
        }

        return ic.intValue();
    }

    private static BigInteger findMaxIterationCount()
    {
        String value = Properties.getPropertyValue(Properties.PKCS12_MAX_IT_COUNT);

        return (value != null) ? new BigInteger(value.trim()) : null;
    }
}
