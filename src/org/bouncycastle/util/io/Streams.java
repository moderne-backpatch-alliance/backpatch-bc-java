package org.bouncycastle.util.io;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class Streams
{
    private static int BUFFER_SIZE = 512;

    public static void drain(InputStream inStr)
        throws IOException
    {
        byte[] bs = new byte[BUFFER_SIZE];
        while (inStr.read(bs, 0, bs.length) >= 0)
        {
        }
    }

    public static byte[] readAll(InputStream inStr)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        pipeAll(inStr, buf);
        return buf.toByteArray();
    }

    public static byte[] readAllLimited(InputStream inStr, int limit)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        pipeAllLimited(inStr, limit, buf);
        return buf.toByteArray();
    }

    public static int readFully(InputStream inStr, byte[] buf)
        throws IOException
    {
        return readFully(inStr, buf, 0, buf.length);
    }

    public static int readFully(InputStream inStr, byte[] buf, int off, int len)
        throws IOException
    {
        int totalRead = 0;
        while (totalRead < len)
        {
            int numRead = inStr.read(buf, off + totalRead, len - totalRead);
            if (numRead < 0)
            {
                break;
            }
            totalRead += numRead;
        }
        return totalRead;
    }

    public static byte[] readLenBytesFully(InputStream inStr, int len)
        throws IOException
    {
        if (len < 0)
        {
            throw new IllegalArgumentException("len cannot be negative");
        }

        // Grow towards len as bytes actually arrive; do not replace with new byte[len] up front:
        // len may be untrusted, and a short input must not drive a large allocation.
        byte[] bytes = new byte[Math.min(len, BUFFER_SIZE)];
        int count = 0;
        while (count < len)
        {
            if (count == bytes.length)
            {
                int expandedLength = (int)Math.min((long)len, 8L * bytes.length);
                byte[] expanded = new byte[expandedLength];
                System.arraycopy(bytes, 0, expanded, 0, count);
                bytes = expanded;
            }

            int numRead = inStr.read(bytes, count, bytes.length - count);
            if (numRead < 0)
            {
                throw new EOFException("premature end of stream");
            }
            count += numRead;
        }

        return bytes;
    }

    public static void pipeAll(InputStream inStr, OutputStream outStr)
        throws IOException
    {
        byte[] bs = new byte[BUFFER_SIZE];
        int numRead;
        while ((numRead = inStr.read(bs, 0, bs.length)) >= 0)
        {
            outStr.write(bs, 0, numRead);
        }
    }

    public static long pipeAllLimited(InputStream inStr, long limit, OutputStream outStr)
        throws IOException
    {
        long total = 0;
        byte[] bs = new byte[BUFFER_SIZE];
        int numRead;
        while ((numRead = inStr.read(bs, 0, bs.length)) >= 0)
        {
            total += numRead;
            if (total > limit)
            {
                throw new StreamOverflowException("Data Overflow");
            }
            outStr.write(bs, 0, numRead);
        }
        return total;
    }
}
