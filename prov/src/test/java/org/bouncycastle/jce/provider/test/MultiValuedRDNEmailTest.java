package org.bouncycastle.jce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * A subject DN can carry an {@code emailAddress} attribute inside a multi-valued RDN (alongside,
 * say, a {@code CN}); such an address must be subjected to email name constraints rather than
 * slipping past them.
 */
public class MultiValuedRDNEmailTest
    extends TestCase
{
    public String getName()
    {
        return "MultiValuedRDNEmail";
    }

    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * End-to-end: a name-constrained intermediate excludes the {@code example.com} mail host, and
     * an end-entity certificate carries {@code user@example.com} inside a multi-valued RDN of its
     * subject DN. Path validation must reject it - the email must be caught by the excluded subtree
     * even though it is not a standalone RDN and not in a SubjectAltName.
     */
    public void testMultiValuedRDNEmailExcludedByNameConstraint()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);

        KeyPair rootKp = kpg.generateKeyPair();
        KeyPair intKp = kpg.generateKeyPair();
        KeyPair eeKp = kpg.generateKeyPair();

        X500Name rootName = new X500Name("CN=BC MultiValuedRDN Root");
        X500Name intName = new X500Name("CN=BC MultiValuedRDN Intermediate");

        // self-signed root (CA), used as the trust anchor
        X509Certificate root = TestCertificateGen.createCert(
            rootName, rootKp.getPrivate(), rootName, "SHA256withRSA", caExtensions(null), rootKp.getPublic());

        // intermediate excludes the example.com mail host
        NameConstraints excludeExampleCom = new NameConstraints(null, new GeneralSubtree[]{
            new GeneralSubtree(new GeneralName(GeneralName.rfc822Name, "example.com"))});
        X509Certificate intermediate = TestCertificateGen.createCert(
            rootName, rootKp.getPrivate(), intName, "SHA256withRSA", caExtensions(excludeExampleCom), intKp.getPublic());

        // end-entity with the email inside a multi-valued RDN of the subject DN
        X509Certificate excludedEE = TestCertificateGen.createCert(
            intName, intKp.getPrivate(), multiValuedSubject("user@example.com"), "SHA256withRSA",
            endEntityExtensions(), eeKp.getPublic());

        try
        {
            validate(excludedEE, intermediate, root);
            fail("multi-valued RDN email under an excluded subtree was not rejected");
        }
        catch (CertPathValidatorException expected)
        {
            // expected - the multi-valued RDN email is caught by the excluded subtree
        }

        // a control: the same shape, but the email is NOT under the excluded host, so it validates
        X509Certificate permittedEE = TestCertificateGen.createCert(
            intName, intKp.getPrivate(), multiValuedSubject("user@other.example.org"), "SHA256withRSA",
            endEntityExtensions(), eeKp.getPublic());

        validate(permittedEE, intermediate, root);
    }

    private static Extensions caExtensions(NameConstraints nameConstraints)
        throws Exception
    {
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        if (nameConstraints != null)
        {
            extGen.addExtension(Extension.nameConstraints, true, nameConstraints);
        }
        return extGen.generate();
    }

    private static Extensions endEntityExtensions()
        throws Exception
    {
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        return extGen.generate();
    }

    private static X500Name multiValuedSubject(String email)
    {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.O, "Test Org");
        builder.addMultiValuedRDN(
            new ASN1ObjectIdentifier[]{BCStyle.CN, BCStyle.EmailAddress},
            new String[]{"John Doe", email});
        return builder.build();
    }

    private static void validate(X509Certificate ee, X509Certificate intermediate, X509Certificate root)
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        List certs = new ArrayList();
        certs.add(ee);
        certs.add(intermediate);
        CertPath certPath = cf.generateCertPath(certs);

        PKIXParameters params = new PKIXParameters(Collections.singleton(new TrustAnchor(root, null)));
        params.setRevocationEnabled(false);

        CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");
        validator.validate(certPath, params);
    }
}
