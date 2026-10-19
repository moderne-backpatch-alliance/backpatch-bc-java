package org.bouncycastle.tls.test;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.util.Vector;

import junit.framework.TestCase;

import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.HandshakeType;
import org.bouncycastle.tls.TlsUtils;

/**
 * A DTLS handshake message whose header declares a length above the peer's
 * getMaxHandshakeMessageSize() must not get a reassembly buffer of that length (CVE-2026-59646).
 * Measured as the bytes the handshaking thread allocates while it reads one such fragment.
 */
public class DTLSReassemblyLimitTest
    extends TestCase
{
    private static final int DECLARED_LENGTH = 16000000;

    public void testServerIgnoresOversizedClientHello()
        throws Exception
    {
        serverReads(100);
        long allocated = serverReads(DECLARED_LENGTH);
        assertTrue("server allocated " + allocated + " bytes for one fragment declaring " + DECLARED_LENGTH,
            allocated < DECLARED_LENGTH / 2);
    }

    public void testClientIgnoresOversizedServerHello()
        throws Exception
    {
        clientReads(100);
        long allocated = clientReads(DECLARED_LENGTH);
        assertTrue("client allocated " + allocated + " bytes for one fragment declaring " + DECLARED_LENGTH,
            allocated < DECLARED_LENGTH / 2);
    }

    private static long serverReads(int declaredLength)
        throws Exception
    {
        OneDatagramTransport transport = new OneDatagramTransport(
            record(HandshakeType.client_hello, declaredLength));
        MockDTLSServer server = new MockDTLSServer();
        long before = allocatedBytes();
        try
        {
            new DTLSServerProtocol().accept(server, transport);
            fail("handshake completed");
        }
        catch (IOException e)
        {
            // the transport ends the handshake after its one datagram
        }
        long allocated = allocatedBytes() - before;
        assertTrue("the fragment was not read", transport.delivered);
        return allocated;
    }

    private static long clientReads(int declaredLength)
        throws Exception
    {
        OneDatagramTransport transport = new OneDatagramTransport(
            record(HandshakeType.server_hello, declaredLength));
        MockDTLSClient client = new MockDTLSClient(null);
        long before = allocatedBytes();
        try
        {
            new DTLSClientProtocol().connect(client, transport);
            fail("handshake completed");
        }
        catch (IOException e)
        {
            // the transport ends the handshake after its one datagram
        }
        long allocated = allocatedBytes() - before;
        assertTrue("the fragment was not read", transport.delivered);
        return allocated;
    }

    /**
     * One DTLS 1.0 handshake record, epoch 0, sequence 0, holding the first 64 bytes of a message
     * whose header declares declaredLength.
     */
    private static byte[] record(short msgType, int declaredLength)
    {
        int fragmentLength = 64;
        byte[] record = new byte[13 + 12 + fragmentLength];
        TlsUtils.writeUint8(ContentType.handshake, record, 0);
        TlsUtils.writeUint8(0xFE, record, 1);
        TlsUtils.writeUint8(0xFF, record, 2);
        TlsUtils.writeUint16(0, record, 3);
        TlsUtils.writeUint48(0L, record, 5);
        TlsUtils.writeUint16(12 + fragmentLength, record, 11);
        TlsUtils.writeUint8(msgType, record, 13);
        TlsUtils.writeUint24(declaredLength, record, 14);
        TlsUtils.writeUint16(0, record, 17);
        TlsUtils.writeUint24(0, record, 19);
        TlsUtils.writeUint24(fragmentLength, record, 22);
        return record;
    }

    private static long allocatedBytes()
        throws Exception
    {
        Object bean = ManagementFactory.getThreadMXBean();
        Method m = Class.forName("com.sun.management.ThreadMXBean").getMethod("getThreadAllocatedBytes",
            new Class[]{ long.class });
        return ((Long)m.invoke(bean, new Object[]{ new Long(Thread.currentThread().getId()) })).longValue();
    }

    /**
     * Delivers one datagram, then fails every further receive so that the handshake ends.
     */
    private static class OneDatagramTransport
        implements DatagramTransport
    {
        private final Vector pending = new Vector();
        boolean delivered = false;

        OneDatagramTransport(byte[] datagram)
        {
            pending.addElement(datagram);
        }

        public int getReceiveLimit()
        {
            return 1500;
        }

        public int getSendLimit()
        {
            return 1500;
        }

        public int receive(byte[] buf, int off, int len, int waitMillis)
            throws IOException
        {
            if (pending.isEmpty())
            {
                throw new IOException("end of test datagrams");
            }
            byte[] datagram = (byte[])pending.remove(0);
            System.arraycopy(datagram, 0, buf, off, datagram.length);
            delivered = true;
            return datagram.length;
        }

        public void send(byte[] buf, int off, int len)
        {
        }

        public void close()
        {
        }
    }
}
