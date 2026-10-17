package org.bouncycastle.pkix.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;
import org.bouncycastle.test.TestResourceFinder;

public class CheckNameConstraintsTest 
    extends TestCase
{
    public void testPKIXCertPathReviewer()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate root = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-root.crt"));
        X509Certificate ca1 = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-ca1.crt"));
        X509Certificate ca2 = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-ca2.crt"));
        X509Certificate leaf = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-leaf.crt"));

        List certchain = new ArrayList();
        certchain.add(root);
        certchain.add(ca1);
        certchain.add(ca2);
        certchain.add(leaf);

        CertPath cp = cf.generateCertPath(certchain);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(root, null));
        PKIXParameters param = new PKIXParameters(trust);

        PKIXCertPathReviewer certPathReviewer = new PKIXCertPathReviewer();
        certPathReviewer.init(cp, param);

        assertFalse(certPathReviewer.isValidCertPath()); // hit
    }

    public void testPKIXCertPathReviewerCapsSubjectAltNames()
        throws Exception
    {
        PKIXCertPathReviewer certPathReviewer = new PKIXCertPathReviewer();
        initReviewerInputs();
        certPathReviewer.init(reviewerPath, reviewerParams);

        assertTrue(hasErrorId(certPathReviewer.getErrors(), "CertPathReviewer.subjAltNameExtError"));
    }

    public void testDeprecatedPKIXCertPathReviewerCapsSubjectAltNames()
        throws Exception
    {
        org.bouncycastle.x509.PKIXCertPathReviewer certPathReviewer = new org.bouncycastle.x509.PKIXCertPathReviewer();
        initReviewerInputs();
        certPathReviewer.init(reviewerPath, reviewerParams);

        assertTrue(hasErrorId(certPathReviewer.getErrors(), "CertPathReviewer.subjAltNameExtError"));
    }

    private CertPath reviewerPath;
    private PKIXParameters reviewerParams;

    private void initReviewerInputs()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate root = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-root.crt"));
        X509Certificate ca1 = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-ca1.crt"));
        X509Certificate ca2 = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-ca2.crt"));
        X509Certificate leaf = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-leaf.crt"));

        List certchain = new ArrayList();
        certchain.add(root);
        certchain.add(ca1);
        certchain.add(ca2);
        certchain.add(leaf);

        reviewerPath = cf.generateCertPath(certchain);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(root, null));
        reviewerParams = new PKIXParameters(trust);
    }

    private static boolean hasErrorId(List[] errors, String id)
    {
        for (int i = 0; i != errors.length; i++)
        {
            for (Iterator it = errors[i].iterator(); it.hasNext();)
            {
                Object msg = it.next();
                if (msg instanceof org.bouncycastle.pkix.util.LocalizedMessage
                    && id.equals(((org.bouncycastle.pkix.util.LocalizedMessage)msg).getId()))
                {
                    return true;
                }
                if (msg instanceof org.bouncycastle.i18n.LocalizedMessage
                    && id.equals(((org.bouncycastle.i18n.LocalizedMessage)msg).getId()))
                {
                    return true;
                }
            }
        }
        return false;
    }

    public void testPKIXCertPathBuilder()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate rootCert = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-root.crt"));
        X509Certificate endCert = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-ca1.crt"));

        // create CertStore to support path building
        List list = new ArrayList();
        list.add(endCert);

        CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
        CertStore                     store = CertStore.getInstance("Collection", params, "BC");

        // build the path
        CertPathBuilder  builder = CertPathBuilder.getInstance("PKIX", "BC");
        X509CertSelector pathConstraints = new X509CertSelector();

        pathConstraints.setCertificate(endCert);

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), pathConstraints);

        buildParams.addCertStore(store);
        buildParams.setDate(new Date(1744869361113L)); // 17th April 2025
        buildParams.setRevocationEnabled(false);
        
        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath                  path = result.getCertPath();

        if (path.getCertificates().size() != 1)
        {
            fail("wrong number of certs in testPKIXCertPathBuilder path");
        }
    }

    public void testPKIXCertPathValidator()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate rootCert = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-root.crt"));
        X509Certificate endCert = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-ca1.crt"));
        
        List list = new ArrayList();
        list.add(endCert);

        CertPath certPath = cf.generateCertPath(list);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);
        param.setDate(new Date(1744869361113L)); // 17th April 2025

        cpv.validate(certPath, param);
    }

    /**
     * RFC 5280 sec. 6.1.3 (b) and (c) apply the accumulated name constraints to every
     * certificate in the path, the target certificate included - the self-issued exemption in
     * sec. 4.2.1.10 is waived for the final certificate, and sec. 6.1.5 (wrap-up) does not
     * revisit name constraints. Both PKIXCertPathReviewer copies drove the check from a loop
     * bound of index &gt; 0, which is the bound the CA-only steps want; index 0 is the end-entity
     * certificate under the standard CertPath ordering, so a leaf whose subject or SAN violated
     * its issuing CA's constraints reviewed as valid with no errors at all, while
     * CertPathValidator("PKIX") rejected the identical chain.
     */
    public void testNameConstraintsAppliedToLeaf()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        KeyPair rootKp = generateKeyPair();
        KeyPair intKp = generateKeyPair();

        X500Name rootDn = new X500Name("CN=NC Test Root CA");
        X500Name intDn = new X500Name("CN=NC Constrained Intermediate CA");

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

        PKIXCertPathReviewer reviewer = new PKIXCertPathReviewer();
        reviewer.init(badPath, badParam);
        assertFalse("pkix reviewer accepted a name-constraint-violating leaf", reviewer.isValidCertPath());
        assertTrue("pkix reviewer did not report the violation against the leaf",
            hasNotification(reviewer.getErrors(0), "CertPathReviewer.notPermittedEmail"));

        org.bouncycastle.x509.PKIXCertPathReviewer legacy = new org.bouncycastle.x509.PKIXCertPathReviewer();
        legacy.init(badPath, badParam);
        assertFalse("legacy reviewer accepted a name-constraint-violating leaf", legacy.isValidCertPath());
        assertTrue("legacy reviewer did not report the violation against the leaf",
            hasNotification(legacy.getErrors(0), "CertPathReviewer.notPermittedEmail"));

        // compatibility control: a leaf inside the permitted subtree still reviews as valid
        CertPath goodPath = generatePath(intDn, intKp, intCert, "host.partner-a.example.com");

        PKIXParameters goodParam = new PKIXParameters(trust);
        goodParam.setRevocationEnabled(false);

        CertPathValidator.getInstance("PKIX", "BC").validate(goodPath, goodParam);

        PKIXCertPathReviewer okReviewer = new PKIXCertPathReviewer();
        okReviewer.init(goodPath, goodParam);
        assertTrue("pkix reviewer rejected a compliant leaf", okReviewer.isValidCertPath());

        org.bouncycastle.x509.PKIXCertPathReviewer okLegacy = new org.bouncycastle.x509.PKIXCertPathReviewer();
        okLegacy.init(goodPath, goodParam);
        assertTrue("legacy reviewer rejected a compliant leaf", okLegacy.isValidCertPath());
    }

    private static KeyPair generateKeyPair()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate sign(JcaX509v3CertificateBuilder builder, PrivateKey signerKey)
        throws Exception
    {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(signerKey);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private static X509Certificate generateRoot(X500Name rootDn, KeyPair rootKp)
        throws Exception
    {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            rootDn, BigInteger.valueOf(1), notBefore(), notAfter(), rootDn, rootKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return sign(builder, rootKp.getPrivate());
    }

    private static X509Certificate generateConstrainedCA(X500Name issuerDn, KeyPair issuerKp,
        X500Name subjectDn, KeyPair subjectKp, String permittedDns)
        throws Exception
    {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuerDn, BigInteger.valueOf(2), notBefore(), notAfter(), subjectDn, subjectKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        GeneralSubtree permitted = new GeneralSubtree(new GeneralName(GeneralName.dNSName, permittedDns));
        builder.addExtension(Extension.nameConstraints, true,
            new NameConstraints(new GeneralSubtree[]{permitted}, null));
        return sign(builder, issuerKp.getPrivate());
    }

    private static CertPath generatePath(X500Name issuerDn, KeyPair issuerKp, X509Certificate issuerCert,
        String leafDns)
        throws Exception
    {
        KeyPair leafKp = generateKeyPair();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuerDn, BigInteger.valueOf(3), notBefore(), notAfter(),
            new X500Name("CN=" + leafDns), leafKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        builder.addExtension(Extension.subjectAlternativeName, false,
            new GeneralNames(new GeneralName(GeneralName.dNSName, leafDns)));
        X509Certificate leafCert = sign(builder, issuerKp.getPrivate());

        List chain = new ArrayList();
        chain.add(leafCert);
        chain.add(issuerCert);

        return CertificateFactory.getInstance("X.509", "BC").generateCertPath(chain);
    }

    private static Date notBefore()
    {
        return new Date(System.currentTimeMillis() - 86400000L);
    }

    private static Date notAfter()
    {
        return new Date(System.currentTimeMillis() + 86400000L * 3650);
    }

    private static boolean hasNotification(List notifications, String id)
    {
        for (int i = 0; i != notifications.size(); i++)
        {
            // the two reviewer copies use different ErrorBundle forks
            Object n = notifications.get(i);
            String nId = (n instanceof org.bouncycastle.pkix.util.ErrorBundle)
                ? ((org.bouncycastle.pkix.util.ErrorBundle)n).getId()
                : ((org.bouncycastle.i18n.ErrorBundle)n).getId();
            if (id.equals(nId))
            {
                return true;
            }
        }
        return false;
    }
}
