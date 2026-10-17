package org.bouncycastle.jce.provider.test;

import org.bouncycastle.jce.X509LDAPCertStoreParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509LDAPCertStoreSpi;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.x509.util.LDAPStoreHelper;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class CertStoreTest
    extends SimpleTest
{

    public void performTest()
        throws Exception
    {
        basicTest();
        orderTest();
        ldapFilterEncodeTest();
        ldapStoreHelperFilterEncodeTest();
    }

    // test written for the backpatch (CVE-2026-0636): the DN value LDAPStoreHelper puts into its LDAP search
    // filters is escaped (RFC 2254)
    private void ldapStoreHelperFilterEncodeTest()
        throws Exception
    {
        LDAPStoreHelper helper = new LDAPStoreHelper(
            new X509LDAPCertStoreParameters.Builder("ldap://localhost:1", "o=test").build());
        Method parseDN = LDAPStoreHelper.class.getDeclaredMethod("parseDN", new Class[]{ String.class, String.class });
        parseDN.setAccessible(true);

        String value = (String)parseDN.invoke(helper, new Object[]{ "CN=chars[*()\\\0], O=Acme", "cn" });
        if (!"chars[\\2a\\28\\29\\5c\\00]".equals(value))
        {
            fail("LDAPStoreHelper filter value not escaped: " + value.replace('\0', '?') + " (NUL shown as ?)");
        }

        value = (String)parseDN.invoke(helper, new Object[]{ "CN=plain name, O=Acme", "cn" });
        if (!"plain name".equals(value))
        {
            fail("plain DN value changed: " + value);
        }
    }

    // test written for the backpatch (CVE-2023-33201): the DN value X509LDAPCertStoreSpi puts into its LDAP
    // search filter is escaped (RFC 2254); its search() wraps the value in '*' wildcards, which stay unescaped
    private void ldapFilterEncodeTest()
        throws Exception
    {
        X509LDAPCertStoreSpi spi = new X509LDAPCertStoreSpi(
            new X509LDAPCertStoreParameters.Builder("ldap://localhost:1", "o=test").build());
        Method parseDN = X509LDAPCertStoreSpi.class.getDeclaredMethod("parseDN", new Class[]{ String.class, String.class });
        parseDN.setAccessible(true);

        String value = (String)parseDN.invoke(spi, new Object[]{ "CN=chars[*()\\\0], O=Acme", "cn" });
        if (!"chars[\\2a\\28\\29\\5c\\00]".equals(value))
        {
            fail("LDAP filter value not escaped: " + value.replace('\0', '?') + " (NUL shown as ?)");
        }

        value = (String)parseDN.invoke(spi, new Object[]{ "CN=plain name, O=Acme", "cn" });
        if (!"plain name".equals(value))
        {
            fail("plain DN value changed: " + value);
        }
    }

    private void basicTest()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate rootCert = (X509Certificate)cf
                .generateCertificate(new ByteArrayInputStream(
                        CertPathTest.rootCertBin));
        X509Certificate interCert = (X509Certificate)cf
                .generateCertificate(new ByteArrayInputStream(
                        CertPathTest.interCertBin));
        X509Certificate finalCert = (X509Certificate)cf
                .generateCertificate(new ByteArrayInputStream(
                        CertPathTest.finalCertBin));
        X509CRL rootCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(
                CertPathTest.rootCrlBin));
        X509CRL interCrl = (X509CRL)cf
                .generateCRL(new ByteArrayInputStream(
                        CertPathTest.interCrlBin));

        // Testing CollectionCertStore generation from List
        List list = new ArrayList();
        list.add(rootCert);
        list.add(interCert);
        list.add(finalCert);
        list.add(rootCrl);
        list.add(interCrl);
        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
        CertStore store = CertStore.getInstance("Collection", ccsp, "BC");

        // Searching for rootCert by subjectDN
        X509CertSelector targetConstraints = new X509CertSelector();
        targetConstraints.setSubject(rootCert.getSubjectX500Principal().getName());
        Collection certs = store.getCertificates(targetConstraints);
        if (certs.size() != 1 || !certs.contains(rootCert))
        {
            fail("rootCert not found by subjectDN");
        }

        // Searching for rootCert by subjectDN encoded as byte
        targetConstraints = new X509CertSelector();
        targetConstraints.setSubject(rootCert.getSubjectX500Principal()
                .getEncoded());
        certs = store.getCertificates(targetConstraints);
        if (certs.size() != 1 || !certs.contains(rootCert))
        {
            fail("rootCert not found by encoded subjectDN");
        }

        // Searching for rootCert by public key encoded as byte
        targetConstraints = new X509CertSelector();
        targetConstraints.setSubjectPublicKey(rootCert.getPublicKey()
                .getEncoded());
        certs = store.getCertificates(targetConstraints);
        if (certs.size() != 1 || !certs.contains(rootCert))
        {
            fail("rootCert not found by encoded public key");
        }

        // Searching for interCert by issuerDN
        targetConstraints = new X509CertSelector();
        targetConstraints.setIssuer(rootCert.getSubjectX500Principal()
                .getEncoded());
        certs = store.getCertificates(targetConstraints);
        if (certs.size() != 2)
        {
            fail("did not found 2 certs");
        }
        if (!certs.contains(rootCert))
        {
            fail("rootCert not found");
        }
        if (!certs.contains(interCert))
        {
            fail("interCert not found");
        }

        // Searching for rootCrl by issuerDN
        X509CRLSelector targetConstraintsCRL = new X509CRLSelector();
        targetConstraintsCRL.addIssuerName(rootCrl.getIssuerX500Principal()
                .getEncoded());
        Collection crls = store.getCRLs(targetConstraintsCRL);
        if (crls.size() != 1 || !crls.contains(rootCrl))
        {
            fail("rootCrl not found");
        }
    }

    private void orderTest()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate rootCert = (X509Certificate)cf
                .generateCertificate(new ByteArrayInputStream(
                        CertPathTest.rootCertBin));
        X509Certificate interCert = (X509Certificate)cf
                .generateCertificate(new ByteArrayInputStream(
                        CertPathTest.interCertBin));
        X509Certificate finalCert = (X509Certificate)cf
                .generateCertificate(new ByteArrayInputStream(
                        CertPathTest.finalCertBin));

        List list = new ArrayList();
        list.add(rootCert);
        list.add(interCert);
        list.add(finalCert);
        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
        CertStore store = CertStore.getInstance("Collection", ccsp, "BC");

        Iterator certs = store.getCertificates(null).iterator();

        if (!certs.next().equals(rootCert))
        {
            fail("root ordering wrong");
        }
        if (!certs.next().equals(interCert))
        {
            fail("mid ordering wrong");
        }
        if (!certs.next().equals(finalCert))
        {
            fail("final ordering wrong");
        }

        list = new ArrayList();
        list.add(finalCert);
        list.add(interCert);
        list.add(rootCert);
        ccsp = new CollectionCertStoreParameters(list);
        store = CertStore.getInstance("Collection", ccsp, "BC");

        certs = store.getCertificates(null).iterator();

        if (!certs.next().equals(finalCert))
        {
            fail("reverse final ordering wrong");
        }
        if (!certs.next().equals(interCert))
        {
            fail("reverse mid ordering wrong");
        }
        if (!certs.next().equals(rootCert))
        {
            fail("reverse root ordering wrong");
        }

        X509CRL rootCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(
                CertPathTest.rootCrlBin));
        X509CRL interCrl = (X509CRL)cf
                .generateCRL(new ByteArrayInputStream(
                        CertPathTest.interCrlBin));

        list = new ArrayList();
        list.add(finalCert);
        list.add(rootCrl);
        list.add(interCrl);

        ccsp = new CollectionCertStoreParameters(list);
        store = CertStore.getInstance("Collection", ccsp, "BC");

        Iterator crls = store.getCRLs(null).iterator();

        if (!crls.next().equals(rootCrl))
        {
            fail("root crl ordering wrong");
        }
        if (!crls.next().equals(interCrl))
        {
            fail("mid crl ordering wrong");
        }

        list = new ArrayList();
        list.add(finalCert);
        list.add(interCrl);
        list.add(rootCrl);
        ccsp = new CollectionCertStoreParameters(list);
        store = CertStore.getInstance("Collection", ccsp, "BC");

        crls = store.getCRLs(null).iterator();

        if (!crls.next().equals(interCrl))
        {
            fail("reverse mid crl ordering wrong");
        }
        if (!crls.next().equals(rootCrl))
        {
            fail("reverse root crl ordering wrong");
        }
    }
    
    public String getName()
    {
        return "CertStore";
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CertStoreTest());
    }

}

