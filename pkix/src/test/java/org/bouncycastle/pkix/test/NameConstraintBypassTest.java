package org.bouncycastle.pkix.test;

import junit.framework.TestCase;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.pkix.PKIXNameConstraintValidator;
import org.bouncycastle.pkix.PKIXNameConstraintValidatorException;
import org.bouncycastle.util.Properties;

/**
 * The bcpkix validator copy: directoryName prefix matching, IPv4-mapped IPv6 addresses and URI host extraction.
 */
public class NameConstraintBypassTest
    extends TestCase
{
    public void testDirectoryNameMustBeAnInitialPrefix()
    {
        GeneralName permitted = new GeneralName(GeneralName.directoryName,
            new X500Name(RFC4519Style.INSTANCE, "ou=permittedSubtree1, o=Test Certificates 2011, c=US"));
        GeneralName prefixSubject = new GeneralName(GeneralName.directoryName,
            new X500Name(RFC4519Style.INSTANCE, "cn=Valid DN nameConstraints EE Certificate Test1, ou=permittedSubtree1, o=Test Certificates 2011, c=US"));
        GeneralName prependedSubject = new GeneralName(GeneralName.directoryName,
            new X500Name(RFC4519Style.INSTANCE, "cn=Valid DN nameConstraints EE Certificate Test1, ou=permittedSubtree1, o=Test Certificates 2011, c=US, o=Injected"));

        assertTrue("prefix subject must be permitted", isPermitted(permitted, prefixSubject));
        assertFalse("subject with an RDN prepended before the permitted sequence must not be permitted",
            isPermitted(permitted, prependedSubject));
    }

    public void testSGP22MatchingOnlyWhenEnabled()
    {
        GeneralName subtree = new GeneralName(GeneralName.directoryName, new X500Name("O=VALID, serialNumber=89034011"));
        GeneralName subject = new GeneralName(GeneralName.directoryName,
            new X500Name("C=ES, O=VALID, CN=VALID EUICC CD, OU=VALID, serialNumber=89034011026140000000000000001332"));

        assertFalse("SGP.22 subject must be rejected by default", isPermitted(subtree, subject));

        System.setProperty(Properties.X509_SGP22_NAME_CONSTRAINTS, "true");
        try
        {
            assertTrue("SGP.22 subject must be permitted when enabled", isPermitted(subtree, subject));
        }
        finally
        {
            System.clearProperty(Properties.X509_SGP22_NAME_CONSTRAINTS);
        }
    }

    public void testIPv4MappedIPv6IsExcludedByIPv4Subtree()
        throws Exception
    {
        byte[] v4Net = new byte[]{ (byte)192, (byte)168, 1, 0, (byte)255, (byte)255, (byte)255, 0 };
        byte[] mappedHost = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte)0xff, (byte)0xff, (byte)192, (byte)168, 1, 5 };

        PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();
        validator.addExcludedSubtree(new GeneralSubtree(new GeneralName(GeneralName.iPAddress, new DEROctetString(v4Net))));
        try
        {
            validator.checkExcluded(new GeneralName(GeneralName.iPAddress, new DEROctetString(mappedHost)));
            fail("IPv4-mapped IPv6 address must be caught by the excluded IPv4 subtree");
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            // expected
        }
    }

    public void testURIHostEndsAtQueryAndFragment()
        throws Exception
    {
        String[] uris = { "https://bank.com?q=1", "https://bank.com#top", "https://user@evil.example@bank.com/" };
        for (int i = 0; i != uris.length; i++)
        {
            PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();
            validator.addExcludedSubtree(new GeneralSubtree(new GeneralName(GeneralName.uniformResourceIdentifier, "bank.com")));
            try
            {
                validator.checkExcluded(new GeneralName(GeneralName.uniformResourceIdentifier, uris[i]));
                fail(uris[i] + " must be caught by the excluded bank.com subtree");
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }

        assertTrue("bracketed IPv6 host must be extracted without brackets and port",
            isPermitted(new GeneralName(GeneralName.uniformResourceIdentifier, "2001:db8::1"),
                new GeneralName(GeneralName.uniformResourceIdentifier, "https://[2001:db8::1]:8443/")));
    }

    private static boolean isPermitted(GeneralName permitted, GeneralName subject)
    {
        PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();
        validator.intersectPermittedSubtree(new GeneralSubtree(permitted));
        try
        {
            validator.checkPermitted(subject);
            return true;
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            return false;
        }
    }
}
