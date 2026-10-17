package org.bouncycastle.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DLBitString;
import org.bouncycastle.util.test.SimpleTest;

/**
 * A BIT STRING whose header declares far more content than the stream holds must fail without
 * first allocating storage for the declared length.
 */
public class BitStringAllocationTest
    extends SimpleTest
{
    private static final int DECLARED_LENGTH = 64 * 1024 * 1024;

    public String getName()
    {
        return "BitStringAllocation";
    }

    public void performTest()
        throws Exception
    {
        testShortBitStringsDecode();
        testTruncatedBitStringAllocatesLittle();
    }

    private void testShortBitStringsDecode()
        throws IOException
    {
        ASN1BitString der = (ASN1BitString)new ASN1InputStream(new GenericStream(new byte[]{ 0x03, 0x03, 0x07, 0x41, (byte)0x80 })).readObject();
        isTrue("DER BIT STRING type", der instanceof DERBitString);
        isEquals(7, der.getPadBits());
        isTrue("DER BIT STRING bytes", areEqual(new byte[]{ 0x41, (byte)0x80 }, der.getBytes()));

        ASN1BitString dl = (ASN1BitString)new ASN1InputStream(new GenericStream(new byte[]{ 0x03, 0x02, 0x07, (byte)0x81 })).readObject();
        isTrue("BIT STRING with non-zero unused bits kept as DL", dl instanceof DLBitString);
        isEquals(7, dl.getPadBits());

        ASN1BitString empty = (ASN1BitString)new ASN1InputStream(new GenericStream(new byte[]{ 0x03, 0x01, 0x00 })).readObject();
        isEquals(0, empty.getBytes().length);
    }

    private void testTruncatedBitStringAllocatesLittle()
        throws Exception
    {
        byte[] enc = new byte[6 + 10];
        enc[0] = 0x03;
        enc[1] = (byte)0x84;
        enc[2] = (byte)(DECLARED_LENGTH >>> 24);
        enc[3] = (byte)(DECLARED_LENGTH >>> 16);
        enc[4] = (byte)(DECLARED_LENGTH >>> 8);
        enc[5] = (byte)DECLARED_LENGTH;

        Object threads = ManagementFactory.getThreadMXBean();
        Method allocated;
        try
        {
            allocated = Class.forName("com.sun.management.ThreadMXBean")
                .getMethod("getThreadAllocatedBytes", new Class[]{ long.class });
        }
        catch (ClassNotFoundException e)
        {
            return; // no per-thread allocation counter on this JVM
        }
        Long id = new Long(Thread.currentThread().getId());

        long before = ((Long)allocated.invoke(threads, new Object[]{ id })).longValue();
        try
        {
            new ASN1InputStream(new GenericStream(enc)).readObject();
            fail("truncated BIT STRING accepted");
        }
        catch (EOFException e)
        {
            // expected
        }
        long used = ((Long)allocated.invoke(threads, new Object[]{ id })).longValue() - before;

        isTrue("parsing a truncated BIT STRING allocated " + used + " bytes", used < DECLARED_LENGTH / 4);
    }

    /**
     * Not a ByteArrayInputStream, so ASN1InputStream cannot bound lengths by the input size.
     */
    private static class GenericStream
        extends InputStream
    {
        private final InputStream in;

        GenericStream(byte[] data)
        {
            this.in = new ByteArrayInputStream(data);
        }

        public int read()
            throws IOException
        {
            return in.read();
        }

        public int read(byte[] buf, int off, int len)
            throws IOException
        {
            return in.read(buf, off, len);
        }
    }

    public static void main(String[] args)
    {
        runTest(new BitStringAllocationTest());
    }
}
