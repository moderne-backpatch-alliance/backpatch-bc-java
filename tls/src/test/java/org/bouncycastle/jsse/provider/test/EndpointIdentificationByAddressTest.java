package org.bouncycastle.jsse.provider.test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import junit.framework.TestCase;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.jsse.BCSSLSocket;
import org.bouncycastle.jsse.util.URLConnectionUtil;

/**
 * A client socket connected by address alone, with HTTPS endpoint identification, must not
 * identify the server by the address it connected to (CVE-2024-34447): the caller has to name
 * the host it meant, with {@link BCSSLSocket#setHost(String)} or a host-taking createSocket.
 */
public class EndpointIdentificationByAddressTest
    extends TestCase
{
    private static final char[] PASSWORD = "password".toCharArray();
    private static final int TIMEOUT_MS = 30000;

    private InetAddress loopback;
    private SSLContext serverContext;
    private SSLContext clientContext;

    protected void setUp()
        throws Exception
    {
        ProviderUtils.setupLowPriority(false);

        loopback = InetAddress.getByAddress(new byte[]{ 127, 0, 0, 1 });

        KeyPair keyPair = TestUtils.generateRSAKeyPair();
        X500Name name = new X500Name("CN=BC endpoint identification test");
        Extensions extensions = new Extensions(new Extension(Extension.subjectAlternativeName, false,
            new DERSequence(new GeneralName(GeneralName.iPAddress, "127.0.0.1")).getEncoded()));
        X509Certificate cert = TestUtils.createCert(name, keyPair.getPrivate(), name, "SHA256withRSA", extensions,
            keyPair.getPublic());

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, PASSWORD);
        keyStore.setKeyEntry("server", keyPair.getPrivate(), PASSWORD, new X509Certificate[]{ cert });
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE);
        kmf.init(keyStore, PASSWORD);
        serverContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
        serverContext.init(kmf.getKeyManagers(), null, null);

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, PASSWORD);
        trustStore.setCertificateEntry("server", cert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE);
        tmf.init(trustStore);
        clientContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
        clientContext.init(null, tmf.getTrustManagers(), null);
    }

    public void testConnectByAddressWithoutHostFailsEndpointIdentification()
        throws Exception
    {
        SSLSocket client = (SSLSocket)clientContext.getSocketFactory().createSocket();
        try
        {
            handshake(client);
            fail("server identified by the address the client connected to");
        }
        catch (IOException e)
        {
            // BCJSSE reports the failed check as a TlsFatalAlert, an IOException but not an SSLException
            assertTrue("handshake failed for another reason: " + e, causedByCertificateException(e));
        }
    }

    public void testSetHostSatisfiesEndpointIdentification()
        throws Exception
    {
        SSLSocket client = (SSLSocket)clientContext.getSocketFactory().createSocket();
        ((BCSSLSocket)client).setHost("127.0.0.1");
        handshake(client);
    }

    public void testURLConnectionUtilFactoryNamesTheHost()
        throws Exception
    {
        SSLSocketFactory factory = new URLConnectionUtil(clientContext.getSocketFactory())
        {
            SSLSocketFactory create(URL url)
            {
                return createSSLSocketFactory(clientContext.getSocketFactory(), url);
            }
        }.create(new URL("https://127.0.0.1/"));

        handshake((SSLSocket)factory.createSocket());
    }

    private void handshake(SSLSocket client)
        throws Exception
    {
        final SSLServerSocket server = (SSLServerSocket)serverContext.getServerSocketFactory().createServerSocket(0, 1,
            loopback);
        Thread serverThread = new Thread()
        {
            public void run()
            {
                try
                {
                    server.setSoTimeout(TIMEOUT_MS);
                    Socket s = server.accept();
                    try
                    {
                        s.setSoTimeout(TIMEOUT_MS);
                        ((SSLSocket)s).startHandshake();
                    }
                    finally
                    {
                        s.close();
                    }
                }
                catch (IOException e)
                {
                    // the client reports the outcome
                }
            }
        };
        serverThread.start();
        try
        {
            SSLParameters parameters = client.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            client.setSSLParameters(parameters);
            client.setSoTimeout(TIMEOUT_MS);
            client.connect(new InetSocketAddress(loopback, server.getLocalPort()), TIMEOUT_MS);
            client.startHandshake();
        }
        finally
        {
            client.close();
            server.close();
            serverThread.join(TIMEOUT_MS);
        }
    }

    private static boolean causedByCertificateException(Throwable t)
    {
        for (; t != null; t = t.getCause())
        {
            if (t instanceof CertificateException)
            {
                return true;
            }
        }
        return false;
    }
}
