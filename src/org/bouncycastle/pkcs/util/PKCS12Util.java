package org.bouncycastle.pkcs.util;

import java.math.BigInteger;
import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * Utility class for PKCS#12 processing.
 */
public class PKCS12Util
{
    private static final BigInteger DEFAULT_MAX_IT_COUNT = BigInteger.valueOf(5000000);

    private static final String PKCS12_MAX_IT_COUNT_PROPERTY = "org.bouncycastle.pkcs12.max_it_count";

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

    // 1.47 has no org.bouncycastle.util.Properties: upstream's property, read as a system property
    private static BigInteger findMaxIterationCount()
    {
        String value = (String)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                return System.getProperty(PKCS12_MAX_IT_COUNT_PROPERTY);
            }
        });

        return (value != null) ? new BigInteger(value.trim()) : null;
    }
}
