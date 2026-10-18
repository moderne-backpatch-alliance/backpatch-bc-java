package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.i18n.LocalizedMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.PKIXNameConstraintValidator;
import org.bouncycastle.jce.provider.PKIXNameConstraintValidatorException;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.x509.PKIXCertPathReviewer;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 * Test class for {@link PKIXNameConstraintValidator}.
 * <p>
 * The field testXYZ is the name to test.
 * <p>
 * The field testXYZIsConstraint must be tested if it is permitted and excluded.
 * <p>
 * The field testXYZIsNotConstraint must be tested if it is not permitted and
 * not excluded.
 * <p>
 * Furthermore there are tests for the intersection and union of test names.
 * 
 */
public class PKIXNameConstraintsTest
    extends SimpleTest
{

    private final static String testEmail = "test@abc.test.com";

    private final static String testEmailIsConstraint[] =
    { "test@abc.test.com", "abc.test.com", ".test.com" };

    private final static String testEmailIsNotConstraint[] =
    { ".abc.test.com", "www.test.com", "test1@abc.test.com", "bc.test.com" };

    private final static String email1[] =
    { "test@test.com", "test@test.com", "test@test.com", "test@abc.test.com",
            "test@test.com", "test@test.com", ".test.com", ".test.com",
            ".test.com", ".test.com", "test.com", "abc.test.com",
            "abc.test1.com", "test.com", "test.com", ".test.com" };

    private final static String email2[] =
    { "test@test.abc.com", "test@test.com", ".test.com", ".test.com",
            "test.com", "test1.com", "test@test.com", ".test.com",
            ".test1.com", "test.com", "test.com", ".test.com", ".test.com",
            "test1.com", ".test.com", "abc.test.com" };

    private final static String emailintersect[] =
    { null, "test@test.com", null, "test@abc.test.com", "test@test.com", null,
            null, ".test.com", null, null, "test.com", "abc.test.com", null,
            null, null, "abc.test.com" };

    private final static String emailunion[][] =
    {
    { "test@test.com", "test@test.abc.com" },
    { "test@test.com" },
    { "test@test.com", ".test.com" },
    { ".test.com" },
    { "test.com" },
    { "test@test.com", "test1.com" },
    { ".test.com", "test@test.com" },
    { ".test.com" },
    { ".test.com", ".test1.com" },
    { ".test.com", "test.com" },
    { "test.com" },
    { ".test.com" },
    { ".test.com", "abc.test1.com" },
    { "test1.com", "test.com" },
    { ".test.com", "test.com" },
    { ".test.com" } };

    private final static String[] dn1 =
    { "O=test org, OU=test org unit, CN=John Doe" };

    private final static String[] dn2 =
    { "O=test org, OU=test org unit" };

    private final static String[][] dnUnion =
    {
    { "O=test org, OU=test org unit" } };

    private final static String[] dnIntersection =
    { "O=test org, OU=test org unit, CN=John Doe" };

    private final static String testDN = "O=test org, OU=test org unit, CN=John Doe";

    private final static String testDNIsConstraint[] =
    { "O=test org, OU=test org unit",
            "O=test org, OU=test org unit, CN=John Doe" };

    private final static String testDNIsNotConstraint[] =
    { "O=test org, OU=test org unit, CN=John Doe2",
            "O=test org, OU=test org unit2",
            "OU=test org unit, O=test org, CN=John Doe",
            "O=test org, OU=test org unit, CN=John Doe, L=USA" };

    private final static String testDNS = "abc.test.com";

    private final static String testDNSIsConstraint[] =
    { "test.com", "abc.test.com", "test.com" };

    private final static String testDNSIsNotConstraint[] =
    { "wwww.test.com", "ww.test.com", "www.test.com" };

    private final static String dns1[] =
    { "www.test.de", "www.test1.de", "www.test.de" };

    private final static String dns2[] =
    { "test.de", "www.test.de", "www.test.de" };

    private final static String dnsintersect[] =
    { "www.test.de", null, null };

    private final static String dnsunion[][] =
    {
    { "test.de" },
    { "www.test1.de", "www.test.de" },
    { "www.test.de" } };

    private final static String testURI = "http://karsten:password@abc.test.com:8080";

    private final static String testURIIsConstraint[] =
    { "abc.test.com", ".test.com" };

    private final static String testURIIsNotConstraint[] =
    { "xyz.test.com", ".abc.test.com" };

    private final static String uri1[] =
    { "www.test.de", ".test.de", "test1.de", ".test.de" };

    private final static String uri2[] =
    { "test.de", "www.test.de", "test1.de", ".test.de" };

    private final static String uriintersect[] =
    { null, "www.test.de", "test1.de", ".test.de" };

    private final static String uriunion[][] =
    {
    { "www.test.de", "test.de" },
    { ".test.de" },
    { "test1.de" },
    { ".test.de" } };

    private final static byte[] testIP =

    { (byte) 192, (byte) 168, 1, 2 };

    private final static byte[][] testIPIsConstraint =
    {
    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0 },
    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 4 } };

    private final static byte[][] testIPIsNotConstraint =
    {
    { (byte) 192, (byte) 168, 3, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 2 },
    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 3 } };

    private final static byte[][] ip1 =
    {
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFE, (byte) 0xFF },
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF },
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0x00 } };

    private final static byte[][] ip2 =
    {
            { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFC, 3 },
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF },
            { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0x00 } };

    private final static byte[][] ipintersect =
    {
            { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFE, (byte) 0xFF },
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF }, null };

    private final static byte[][][] ipunion =
    {
            {
                    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFE, (byte) 0xFF },
                    { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFC, 3 } },
            {
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF } },
            {
                    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFF, (byte) 0x00 },
                    { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFF, (byte) 0x00 } } };

    public String getName()
    {
        return "PKIXNameConstraintsTest";
    }

    public void performTest() throws Exception
    {
        testConstraints(GeneralName.rfc822Name, testEmail,
            testEmailIsConstraint, testEmailIsNotConstraint, email1, email2,
            emailunion, emailintersect);
        testConstraints(GeneralName.dNSName, testDNS, testDNSIsConstraint,
            testDNSIsNotConstraint, dns1, dns2, dnsunion, dnsintersect);
        testConstraints(GeneralName.directoryName, testDN, testDNIsConstraint,
            testDNIsNotConstraint, dn1, dn2, dnUnion, dnIntersection);
        testConstraints(GeneralName.uniformResourceIdentifier, testURI,
            testURIIsConstraint, testURIIsNotConstraint, uri1, uri2, uriunion,
            uriintersect);
        testConstraints(GeneralName.iPAddress, testIP, testIPIsConstraint,
            testIPIsNotConstraint, ip1, ip2, ipunion, ipintersect);
        testPKIXCertPathReviewerCapsSubjectAltNames();

        testNameConstraintBypasses();
        testDNSTrailingDot();
        testIPv4MappedIPv6();
        testURIHostExtraction();
        testNameConstraintsAppliedToLeaf();
    }

    /**
     * CVE-2026-71889: upstream 06dcff2f5's test for the legacy reviewer, with 1.46's X509V3CertificateGenerator
     * in place of the bcpkix certificate builder.
     *
     * RFC 5280 sec. 6.1.3 (b) and (c) apply the accumulated name constraints to every
     * certificate in the path, the target certificate included - the self-issued exemption in
     * sec. 4.2.1.10 is waived for the final certificate, and sec. 6.1.5 (wrap-up) does not
     * revisit name constraints. PKIXCertPathReviewer drove the check from a loop
     * bound of index &gt; 0, which is the bound the CA-only steps want; index 0 is the end-entity
     * certificate under the standard CertPath ordering, so a leaf whose subject or SAN violated
     * its issuing CA's constraints reviewed as valid with no errors at all, while
     * CertPathValidator("PKIX") rejected the identical chain.
     */
    private void testNameConstraintsAppliedToLeaf()
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPair rootKp = generateKeyPair();
        KeyPair intKp = generateKeyPair();

        X500Principal rootDn = new X500Principal("CN=NC Test Root CA");
        X500Principal intDn = new X500Principal("CN=NC Constrained Intermediate CA");

        X509Certificate rootCert = generateRoot(rootDn, rootKp);
        X509Certificate intCert = generateConstrainedCA(rootDn, rootKp, intDn, intKp, "partner-a.example.com");

        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        // a leaf the constrained CA was never authorised to vouch for
        CertPath badPath = generatePath(intDn, intKp, intCert, "attacker.evil.com");

        PKIXParameters badParam = new PKIXParameters(trust);
        badParam.setRevocationEnabled(false);

        // ground truth: the trust-deciding validator rejects it
        try
        {
            CertPathValidator.getInstance("PKIX", "BC").validate(badPath, badParam);
            fail("CertPathValidator accepted a name-constraint-violating leaf");
        }
        catch (CertPathValidatorException e)
        {
            // expected
        }

        PKIXCertPathReviewer legacy = new PKIXCertPathReviewer();
        legacy.init(badPath, badParam);
        if (legacy.isValidCertPath())
        {
            fail("legacy reviewer accepted a name-constraint-violating leaf");
        }
        if (!hasErrorId(new List[]{ legacy.getErrors(0) }, "CertPathReviewer.notPermittedEmail"))
        {
            fail("legacy reviewer did not report the violation against the leaf");
        }

        // compatibility control: a leaf inside the permitted subtree still reviews as valid
        CertPath goodPath = generatePath(intDn, intKp, intCert, "host.partner-a.example.com");

        PKIXParameters goodParam = new PKIXParameters(trust);
        goodParam.setRevocationEnabled(false);

        CertPathValidator.getInstance("PKIX", "BC").validate(goodPath, goodParam);

        PKIXCertPathReviewer okLegacy = new PKIXCertPathReviewer();
        okLegacy.init(goodPath, goodParam);
        if (!okLegacy.isValidCertPath())
        {
            fail("legacy reviewer rejected a compliant leaf");
        }
    }

    private static KeyPair generateKeyPair()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509V3CertificateGenerator newGenerator(X500Principal issuerDn, BigInteger serial, X500Principal subjectDn, KeyPair subjectKp)
    {
        X509V3CertificateGenerator gen = new X509V3CertificateGenerator();
        gen.setSerialNumber(serial);
        gen.setIssuerDN(issuerDn);
        gen.setNotBefore(new Date(System.currentTimeMillis() - 86400000L));
        gen.setNotAfter(new Date(System.currentTimeMillis() + 86400000L * 3650));
        gen.setSubjectDN(subjectDn);
        gen.setPublicKey(subjectKp.getPublic());
        gen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        return gen;
    }

    private static X509Certificate generateRoot(X500Principal rootDn, KeyPair rootKp)
        throws Exception
    {
        X509V3CertificateGenerator gen = newGenerator(rootDn, BigInteger.valueOf(1), rootDn, rootKp);
        gen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        gen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return gen.generate(rootKp.getPrivate(), "BC");
    }

    private static X509Certificate generateConstrainedCA(X500Principal issuerDn, KeyPair issuerKp,
        X500Principal subjectDn, KeyPair subjectKp, String permittedDns)
        throws Exception
    {
        X509V3CertificateGenerator gen = newGenerator(issuerDn, BigInteger.valueOf(2), subjectDn, subjectKp);
        gen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
        gen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        Vector permitted = new Vector();
        permitted.addElement(new GeneralSubtree(new GeneralName(GeneralName.dNSName, permittedDns)));
        gen.addExtension(X509Extensions.NameConstraints, true, new NameConstraints(permitted, null));
        return gen.generate(issuerKp.getPrivate(), "BC");
    }

    private static CertPath generatePath(X500Principal issuerDn, KeyPair issuerKp, X509Certificate issuerCert,
        String leafDns)
        throws Exception
    {
        KeyPair leafKp = generateKeyPair();
        X509V3CertificateGenerator gen = newGenerator(issuerDn, BigInteger.valueOf(3), new X500Principal("CN=" + leafDns), leafKp);
        gen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        gen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        gen.addExtension(X509Extensions.SubjectAlternativeName, false,
            new GeneralNames(new GeneralName(GeneralName.dNSName, leafDns)));
        X509Certificate leafCert = gen.generate(issuerKp.getPrivate(), "BC");

        List chain = new ArrayList();
        chain.add(leafCert);
        chain.add(issuerCert);

        return CertificateFactory.getInstance("X.509", "BC").generateCertPath(chain);
    }

    // CVE-2026-8763: upstream 2c28b253a's test
    private void testNameConstraintBypasses()
        throws Exception
    {
        // An RFC 1034 root-label trailing dot must not let a host escape an excluded rfc822Name or
        // URI subtree, matching the dNSName canonicalisation.
        PKIXNameConstraintValidator emailV = new PKIXNameConstraintValidator();
        emailV.addExcludedSubtree(new GeneralSubtree(new GeneralName(GeneralName.rfc822Name, "bank.com")));
        try
        {
            emailV.checkExcluded(new GeneralName(GeneralName.rfc822Name, "ceo@bank.com."));
            fail("trailing-dot email must be caught by the excluded bank.com subtree");
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            // expected
        }

        PKIXNameConstraintValidator uriV = new PKIXNameConstraintValidator();
        uriV.addExcludedSubtree(new GeneralSubtree(new GeneralName(GeneralName.uniformResourceIdentifier, "competitor.example")));
        try
        {
            uriV.checkExcluded(new GeneralName(GeneralName.uniformResourceIdentifier, "https://competitor.example./"));
            fail("trailing-dot URI host must be caught by the excluded competitor.example subtree");
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            // expected
        }
    }

    // CVE-2026-8763: tests written for the backpatch (upstream b2769e8e7's IPv4-mapped IPv6 and URI host hunks have none)
    private boolean isPermitted(GeneralName permitted, GeneralName subject)
    {
        PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();
        validator.intersectPermittedSubtree(new DERSequence(new GeneralSubtree(permitted)));
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

    private void testIPv4MappedIPv6()
        throws Exception
    {
        byte[] v4Net = new byte[]{ (byte)192, (byte)168, 1, 0, (byte)255, (byte)255, (byte)255, 0 };
        byte[] mappedHost = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte)0xff, (byte)0xff, (byte)192, (byte)168, 1, 5 };
        byte[] v4Host = new byte[]{ (byte)192, (byte)168, 1, 5 };
        byte[] mappedNet = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte)0xff, (byte)0xff, (byte)192, (byte)168, 1, 0,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 0 };

        PKIXNameConstraintValidator v4V = new PKIXNameConstraintValidator();
        v4V.addExcludedSubtree(new GeneralSubtree(new GeneralName(GeneralName.iPAddress, new DEROctetString(v4Net))));
        try
        {
            v4V.checkExcluded(new GeneralName(GeneralName.iPAddress, new DEROctetString(mappedHost)));
            fail("IPv4-mapped IPv6 address must be caught by the excluded IPv4 subtree");
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            // expected
        }

        PKIXNameConstraintValidator mappedV = new PKIXNameConstraintValidator();
        mappedV.addExcludedSubtree(new GeneralSubtree(new GeneralName(GeneralName.iPAddress, new DEROctetString(mappedNet))));
        try
        {
            mappedV.checkExcluded(new GeneralName(GeneralName.iPAddress, new DEROctetString(v4Host)));
            fail("IPv4 address must be caught by the excluded IPv4-mapped IPv6 subtree");
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            // expected
        }

        if (!isPermitted(new GeneralName(GeneralName.iPAddress, new DEROctetString(v4Net)),
            new GeneralName(GeneralName.iPAddress, new DEROctetString(mappedHost))))
        {
            fail("IPv4-mapped IPv6 address inside a permitted IPv4 subtree must be permitted");
        }
        if (isPermitted(new GeneralName(GeneralName.iPAddress, new DEROctetString(v4Net)),
            new GeneralName(GeneralName.iPAddress, new DEROctetString(
                new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte)0xff, (byte)0xff, 10, 0, 0, 1 }))))
        {
            fail("IPv4-mapped IPv6 address outside a permitted IPv4 subtree must not be permitted");
        }
    }

    private void testURIHostExtraction()
        throws Exception
    {
        String[] excludedUris = {
            "https://bank.com?q=1",
            "https://bank.com#top",
            "https://user@evil.example@bank.com/",
        };
        for (int i = 0; i != excludedUris.length; i++)
        {
            PKIXNameConstraintValidator uriV = new PKIXNameConstraintValidator();
            uriV.addExcludedSubtree(new GeneralSubtree(new GeneralName(GeneralName.uniformResourceIdentifier, "bank.com")));
            try
            {
                uriV.checkExcluded(new GeneralName(GeneralName.uniformResourceIdentifier, excludedUris[i]));
                fail("URI " + excludedUris[i] + " must be caught by the excluded bank.com subtree");
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }

        if (!isPermitted(new GeneralName(GeneralName.uniformResourceIdentifier, "bank.com"),
            new GeneralName(GeneralName.uniformResourceIdentifier, "https://user:pw@bank.com:8443/a/b?c=d#e")))
        {
            fail("host with port, path, query and fragment must be permitted");
        }
        if (!isPermitted(new GeneralName(GeneralName.uniformResourceIdentifier, "2001:db8::1"),
            new GeneralName(GeneralName.uniformResourceIdentifier, "https://[2001:db8::1]:8443/")))
        {
            fail("bracketed IPv6 host must be extracted without brackets and port");
        }
    }

    // CVE-2026-8763: test written for the backpatch (dNSName and sub-domain forms), as on 1.78.1
    private void testDNSTrailingDot()
        throws Exception
    {
        String[][] cases = {
            { "bank.com", "bank.com." },
            { "bank.com", "www.bank.com." },
            { ".bank.com", "www.bank.com." }
        };
        for (int i = 0; i != cases.length; i++)
        {
            PKIXNameConstraintValidator dnsV = new PKIXNameConstraintValidator();
            dnsV.addExcludedSubtree(new GeneralSubtree(new GeneralName(GeneralName.dNSName, cases[i][0])));
            try
            {
                dnsV.checkExcluded(new GeneralName(GeneralName.dNSName, cases[i][1]));
                fail("trailing-dot dNSName " + cases[i][1] + " must be caught by the excluded " + cases[i][0] + " subtree");
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }

        PKIXNameConstraintValidator emailV = new PKIXNameConstraintValidator();
        emailV.addExcludedSubtree(new GeneralSubtree(new GeneralName(GeneralName.rfc822Name, ".bank.com")));
        try
        {
            emailV.checkExcluded(new GeneralName(GeneralName.rfc822Name, "ceo@www.bank.com."));
            fail("trailing-dot email must be caught by the excluded .bank.com subtree");
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            // expected
        }
    }

    // CVE-2025-8916: upstream's certificates (bc-test-data 9cc1de5 pkix/mal-*.crt, from 310b30a4f's test); the
    // assertion on the cap's error is written for the backpatch, as upstream's own reviewer test passes unfixed
    private void testPKIXCertPathReviewerCapsSubjectAltNames()
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate root = (X509Certificate)cf.generateCertificate(getClass().getResourceAsStream("mal-root.crt"));
        X509Certificate ca1 = (X509Certificate)cf.generateCertificate(getClass().getResourceAsStream("mal-ca1.crt"));
        X509Certificate ca2 = (X509Certificate)cf.generateCertificate(getClass().getResourceAsStream("mal-ca2.crt"));
        X509Certificate leaf = (X509Certificate)cf.generateCertificate(getClass().getResourceAsStream("mal-leaf.crt"));

        List certchain = new ArrayList();
        certchain.add(root);
        certchain.add(ca1);
        certchain.add(ca2);
        certchain.add(leaf);

        CertPath reviewerPath = cf.generateCertPath(certchain);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(root, null));
        PKIXParameters reviewerParams = new PKIXParameters(trust);

        PKIXCertPathReviewer certPathReviewer = new PKIXCertPathReviewer();
        certPathReviewer.init(reviewerPath, reviewerParams);

        if (certPathReviewer.isValidCertPath())
        {
            fail("reviewer accepted the path");
        }
        if (!hasErrorId(certPathReviewer.getErrors(), "CertPathReviewer.subjAltNameExtError"))
        {
            fail("reviewer did not refuse the subject alt names");
        }
    }

    private static boolean hasErrorId(List[] errors, String id)
    {
        for (int i = 0; i != errors.length; i++)
        {
            for (Iterator it = errors[i].iterator(); it.hasNext();)
            {
                Object msg = it.next();
                if (msg instanceof LocalizedMessage && id.equals(((LocalizedMessage)msg).getId()))
                {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Tests string based GeneralNames for inclusion or exclusion.
     * 
     * @param nameType The {@link GeneralName} type to test.
     * @param testName The name to test.
     * @param testNameIsConstraint The names where <code>testName</code> must
     *            be included and excluded.
     * @param testNameIsNotConstraint The names where <code>testName</code>
     *            must not be excluded and included.
     * @param testNames1 Operand 1 of test names to use for union and
     *            intersection testing.
     * @param testNames2 Operand 2 of test names to use for union and
     *            intersection testing.
     * @param testUnion The union results.
     * @param testInterSection The intersection results.
     * @throws Exception If an unexpected exception occurs.
     */
    private void testConstraints(
        int nameType,
        String testName,
        String[] testNameIsConstraint,
        String[] testNameIsNotConstraint,
        String[] testNames1,
        String[] testNames2,
        String[][] testUnion,
        String[] testInterSection) throws Exception
    {
        for (int i = 0; i < testNameIsConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new DERSequence(new GeneralSubtree(
                new GeneralName(nameType, testNameIsConstraint[i]))));
            constraintValidator.checkPermitted(new GeneralName(nameType, testName));
        }
        for (int i = 0; i < testNameIsNotConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new DERSequence(new GeneralSubtree(
                new GeneralName(nameType, testNameIsNotConstraint[i]))));
            try
            {
                constraintValidator.checkPermitted(new GeneralName(nameType, testName));
                fail("not permitted name allowed: " + nameType);
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }
        for (int i = 0; i < testNameIsConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, testNameIsConstraint[i])));
            try
            {
                constraintValidator.checkExcluded(new GeneralName(nameType, testName));
                fail("excluded name missed: " + nameType);
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }
        for (int i = 0; i < testNameIsNotConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, testNameIsNotConstraint[i])));
            constraintValidator.checkExcluded(new GeneralName(nameType, testName));
        }
        for (int i = 0; i < testNames1.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, testNames1[i])));
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, testNames2[i])));
            PKIXNameConstraintValidator constraints2 = new PKIXNameConstraintValidator();
            for (int j = 0; j < testUnion[i].length; j++)
            {
                constraints2.addExcludedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, testUnion[i][j])));
            }
            if (!constraints2.equals(constraintValidator))
            {
                fail("union wrong: " + nameType);
            }
            constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new DERSequence(new GeneralSubtree(
                new GeneralName(nameType, testNames1[i]))));
            constraintValidator.intersectPermittedSubtree(new DERSequence(new GeneralSubtree(
                new GeneralName(nameType, testNames2[i]))));
            constraints2 = new PKIXNameConstraintValidator();
            if (testInterSection[i] != null)
            {
                constraints2.intersectPermittedSubtree(new DERSequence(new GeneralSubtree(
                    new GeneralName(nameType, testInterSection[i]))));
            }
            else
            {
                constraints2.intersectEmptyPermittedSubtree(nameType);
            }
            if (!constraints2.equals(constraintValidator))
            {
                fail("intersection wrong: " + nameType);
            }
        }
    }

    /**
     * Tests byte array based GeneralNames for inclusion or exclusion.
     * 
     * @param nameType The {@link GeneralName} type to test.
     * @param testName The name to test.
     * @param testNameIsConstraint The names where <code>testName</code> must
     *            be included and excluded.
     * @param testNameIsNotConstraint The names where <code>testName</code>
     *            must not be excluded and included.
     * @param testNames1 Operand 1 of test names to use for union and
     *            intersection testing.
     * @param testNames2 Operand 2 of test names to use for union and
     *            intersection testing.
     * @param testUnion The union results.
     * @param testInterSection The intersection results.
     * @throws Exception If an unexpected exception occurs.
     */
    private void testConstraints(
        int nameType,
        byte[] testName,
        byte[][] testNameIsConstraint,
        byte[][] testNameIsNotConstraint,
        byte[][] testNames1,
        byte[][] testNames2,
        byte[][][] testUnion,
        byte[][] testInterSection) throws Exception
    {
        for (int i = 0; i < testNameIsConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new DERSequence(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(
                    testNameIsConstraint[i])))));
            constraintValidator.checkPermitted(new GeneralName(nameType,
                new DEROctetString(testName)));
        }
        for (int i = 0; i < testNameIsNotConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new DERSequence(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(
                    testNameIsNotConstraint[i])))));
            try
            {
                constraintValidator.checkPermitted(new GeneralName(nameType,
                    new DEROctetString(testName)));
                fail("not permitted name allowed: " + nameType);
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }
        for (int i = 0; i < testNameIsConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, new DEROctetString(testNameIsConstraint[i]))));
            try
            {
                constraintValidator.checkExcluded(new GeneralName(nameType,
                    new DEROctetString(testName)));
                fail("excluded name missed: " + nameType);
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }
        for (int i = 0; i < testNameIsNotConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, new DEROctetString(testNameIsNotConstraint[i]))));
            constraintValidator.checkExcluded(new GeneralName(nameType,
                new DEROctetString(testName)));
        }
        for (int i = 0; i < testNames1.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, new DEROctetString(testNames1[i]))));
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, new DEROctetString(testNames2[i]))));
            PKIXNameConstraintValidator constraints2 = new PKIXNameConstraintValidator();
            for (int j = 0; j < testUnion[i].length; j++)
            {
                constraints2.addExcludedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, new DEROctetString(
                        testUnion[i][j]))));
            }
            if (!constraints2.equals(constraintValidator))
            {
                fail("union wrong: " + nameType);
            }
            constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new DERSequence(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(testNames1[i])))));
            constraintValidator.intersectPermittedSubtree(new DERSequence(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(testNames2[i])))));
            constraints2 = new PKIXNameConstraintValidator();
            if (testInterSection[i] != null)
            {
                constraints2.intersectPermittedSubtree(new DERSequence(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(
                    testInterSection[i])))));
            }
            else
            {
                constraints2.intersectEmptyPermittedSubtree(nameType);
            }

            if (!constraints2.equals(constraintValidator))
            {
                fail("intersection wrong: " + nameType);
            }
        }
    }

    public static void main(String[] args)
    {
        runTest(new PKIXNameConstraintsTest());
    }
}
