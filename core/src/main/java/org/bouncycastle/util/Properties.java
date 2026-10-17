package org.bouncycastle.util;

import java.math.BigInteger;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * Utility method for accessing system properties.
 */
public class Properties
{
    /**
     * Upper bound on the RFC 4211 PKMAC / CMP password-based-MAC iteration count honoured when no
     * explicit ceiling was supplied to {@link org.bouncycastle.cert.crmf.PKMACBuilder}. The count
     * travels in the (unauthenticated) PBMParameter of an incoming CMP message and drives an
     * iterated hash, so an unbounded count makes verifying an attacker-supplied message a
     * CPU-exhaustion vector. Default 10,000,000, generous enough for any legitimate setting. Read
     * via {@link #getPropertyValue(String)}.
     */
    public static final String PKMAC_MAX_ITERATION_COUNT = "org.bouncycastle.pkmac.max_iteration_count";

    /**
     * Upper bound on the PBE iteration count honoured when BC takes that count from an
     * untrusted encoding: decrypting a PBES2-protected PKCS#8 / PEM private key or PKCS#12
     * bag, verifying an RFC 9579 PBMAC1, unwrapping a CMS password recipient, and the raw JCA
     * PBKDF2 provider (both the {@code SecretKeyFactory} derivation and the
     * {@code AlgorithmParameters} parse a {@code Cipher} performs for PBES2). It also bounds the
     * legacy PBES1 (PKCS#5 scheme 1) and PKCS#12 PBE families in the raw JCA provider: the
     * {@code AlgorithmParameters} parse, and every {@code Cipher}, {@code Mac} and
     * {@code SecretKeyFactory} derivation, whichever provider decoded the parameters. In each case the
     * key-derivation parameters travel inside an unauthenticated container, so an unbounded
     * count makes processing attacker-supplied material a CPU-exhaustion vector. The PKCS#12
     * key store derives through the same provider code, so an org.bouncycastle.pkcs12.max_it_count raised
     * above this bound needs this one raised too. Default
     * 10,000,000 - the count RFC 8018 sec. 4.2 names as possibly appropriate for especially
     * critical keys, so generous enough for deliberately strong settings. Read via
     * {@link #getPropertyValue(String)}.
     */
    public static final String PBE_MAX_ITERATION_COUNT = "org.bouncycastle.pbe.max_iteration_count";

    /**
     * Upper bound, in bytes, on the scrypt working memory (~128 * N * r) honoured when decrypting
     * a PBES2-protected PKCS#8 / PEM private key. As with {@link #PBE_MAX_ITERATION_COUNT} the
     * scrypt cost travels in the unauthenticated container, so an unbounded cost is a
     * memory-exhaustion vector. Default 1073741824 (1 GiB). Read via {@link #getPropertyValue(String)}.
     */
    public static final String PBE_MAX_SCRYPT_MEMORY = "org.bouncycastle.pbe.max_scrypt_memory";

    /**
     * Upper bound on the PBKDF2 iteration count honoured when deriving the integrity-MAC key of a
     * BCFKS keystore during load. The KDF runs on parameters taken from the (not-yet-verified)
     * keystore, so an unbounded iteration count is a pre-integrity CPU-exhaustion vector. Default
     * 5,000,000 (the BCFKS writer uses ~51,200). Read via {@link #getPropertyValue(String)}.
     */
    public static final String BCFKS_MAX_IT_COUNT = "org.bouncycastle.bcfks.max_it_count";

    /**
     * Upper bound, in bytes, on the working memory (~128 * N * r) of the scrypt KDF honoured when
     * deriving the integrity-MAC key of a BCFKS keystore during load. As with
     * {@link #BCFKS_MAX_IT_COUNT} the scrypt cost parameters are taken from the not-yet-verified
     * keystore, so an unbounded cost is a pre-integrity memory-exhaustion vector. Default
     * 1073741824 (1 GiB); the BCFKS writer uses N=16384, r=8 (~16 MiB). Read via
     * {@link #getPropertyValue(String)}.
     */
    public static final String BCFKS_MAX_SCRYPT_MEMORY = "org.bouncycastle.bcfks.max_scrypt_memory";

    private Properties()
    {
    }

    /**
     * Opt in to the relaxed directoryName name-constraint matching required by GSMA SGP.22 v2.5
     * (Remote SIM Provisioning), sections 4.5.2.1.0.2 / 4.5.2.1.0.3. When set, a permitted-subtree
     * RDN is satisfied by any matching subject RDN regardless of position, additional subject
     * attributes beyond those named in the subtree are tolerated, and a serialNumber RDN is matched
     * with a startsWith comparison wherever it appears. This is deliberately looser than the
     * contiguous-prefix DN matching mandated by RFC 5280 7.1, so it defaults to off and must be
     * enabled explicitly; BC's default validation remains RFC 5280 strict. See github #2327.
     * Read via {@link #isOverrideSet(String)}.
     */
    public static final String X509_SGP22_NAME_CONSTRAINTS = "org.bouncycastle.x509.sgp22_name_constraints";

    private static final ThreadLocal threadProperties = new ThreadLocal();

    /**
     * Return whether a particular override has been set to true.
     *
     * @param propertyName the property name for the override.
     * @return true if the property is set to "true", false otherwise.
     */
    public static boolean isOverrideSet(String propertyName)
    {
        try
        {
            return isSetTrue(getPropertyValue(propertyName));
        }
        catch (AccessControlException e)
        {
            return false;
        }
    }

    /**
     * Return whether a particular override has been set to false.
     *
     * @param propertyName the property name for the override.
     * @param isTrue true if the override should be true, false otherwise.
     * @return true if the property is set to the value of isTrue, false otherwise.
     */
    public static boolean isOverrideSetTo(String propertyName, boolean isTrue)
    {
        try
        {
            String propertyValue = getPropertyValue(propertyName);
            if (isTrue)
            {
                return isSetTrue(propertyValue);
            }
            return isSetFalse(propertyValue);
        }
        catch (AccessControlException e)
        {
            return false;
        }
    }

    /**
     * Enable the specified override property for the current thread only.
     *
     * @param propertyName the property name for the override.
     * @param enable true if the override should be enabled, false if it should be disabled.
     * @return true if the override was already set true, false otherwise.
     */
    public static boolean setThreadOverride(String propertyName, boolean enable)
    {
        boolean isSet = isOverrideSet(propertyName);

        Map localProps = (Map)threadProperties.get();
        if (localProps == null)
        {
            localProps = new HashMap();

            threadProperties.set(localProps);
        }

        localProps.put(propertyName, enable ? "true" : "false");

        return isSet;
    }

    /**
     * Remove any value for the specified override property for the current thread only.
     *
     * @param propertyName the property name for the override.
     * @return true if the override was already set true in thread local, false otherwise.
     */
    public static boolean removeThreadOverride(String propertyName)
    {
        Map localProps = (Map)threadProperties.get();
        if (localProps != null)
        {
            String p = (String)localProps.remove(propertyName);
            if (p != null)
            {
                if (localProps.isEmpty())
                {
                    threadProperties.remove();
                }

                return "true".equals(Strings.toLowerCase(p));
            }
        }

        return false;
    }

    public static BigInteger asBigInteger(String propertyName)
    {
        String p = getPropertyValue(propertyName);

        if (p != null)
        {
            return new BigInteger(p);
        }

        return null;
    }

    public static Set<String> asKeySet(String propertyName)
    {
        Set<String> set = new HashSet<String>();

        String p = getPropertyValue(propertyName);

        if (p != null)
        {
            StringTokenizer sTok = new StringTokenizer(p, ",");
            while (sTok.hasMoreElements())
            {
                set.add(Strings.toLowerCase(sTok.nextToken()).trim());
            }
        }

        return Collections.unmodifiableSet(set);
    }

    public static String getPropertyValue(final String propertyName)
    {
        String val = (String)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                return Security.getProperty(propertyName);
            }
        });
        if (val != null)
        {
            return val;
        }

        Map localProps = (Map)threadProperties.get();
        if (localProps != null)
        {
            String p = (String)localProps.get(propertyName);
            if (p != null)
            {
                return p;
            }
        }

        return (String)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                return System.getProperty(propertyName);
            }
        });
    }

    private static boolean isSetFalse(String p)
    {
        if (p == null || p.length() != 5)
        {
            return false;
        }

        return (p.charAt(0) == 'f' || p.charAt(0) == 'F')
            && (p.charAt(1) == 'a' || p.charAt(1) == 'A')
            && (p.charAt(2) == 'l' || p.charAt(2) == 'L')
            && (p.charAt(3) == 's' || p.charAt(3) == 'S')
            && (p.charAt(4) == 'e' || p.charAt(4) == 'E');
    }

    private static boolean isSetTrue(String p)
    {
        if (p == null || p.length() != 4)
        {
            return false;
        }

        return (p.charAt(0) == 't' || p.charAt(0) == 'T')
            && (p.charAt(1) == 'r' || p.charAt(1) == 'R')
            && (p.charAt(2) == 'u' || p.charAt(2) == 'U')
            && (p.charAt(3) == 'e' || p.charAt(3) == 'E');
    }
}
