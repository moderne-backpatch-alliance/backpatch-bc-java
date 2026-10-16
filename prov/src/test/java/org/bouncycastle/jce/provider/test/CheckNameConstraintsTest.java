package org.bouncycastle.jce.provider.test;

import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
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
import org.bouncycastle.i18n.LocalizedMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.PKIXCertPathReviewer;

public class CheckNameConstraintsTest
    extends TestCase
{
    public void testPKIXCertPathReviewer()
        throws Exception
    {
        PKIXCertPathReviewer certPathReviewer = new PKIXCertPathReviewer();
        initReviewerInputs();
        certPathReviewer.init(reviewerPath, reviewerParams);

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

    public void testPKIXCertPathBuilder()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate rootCert = (X509Certificate)cf.generateCertificate(getClass().getResourceAsStream("mal-root.crt"));
        X509Certificate endCert = (X509Certificate)cf.generateCertificate(getClass().getResourceAsStream("mal-ca1.crt"));

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

        X509Certificate rootCert = (X509Certificate)cf.generateCertificate(getClass().getResourceAsStream("mal-root.crt"));
        X509Certificate endCert = (X509Certificate)cf.generateCertificate(getClass().getResourceAsStream("mal-ca1.crt"));

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

    private CertPath reviewerPath;
    private PKIXParameters reviewerParams;

    private void initReviewerInputs()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

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
                if (msg instanceof LocalizedMessage && id.equals(((LocalizedMessage)msg).getId()))
                {
                    return true;
                }
            }
        }
        return false;
    }
}
