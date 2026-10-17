package org.bouncycastle.asn1;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

class DefiniteLengthInputStream
        extends LimitedInputStream
{
    private static final byte[] EMPTY_BYTES = new byte[0];

    private static final int BUFFER_SIZE = 4096;

    private final int _originalLength;
    private int _remaining;

    DefiniteLengthInputStream(
        InputStream in,
        int         length)
    {
        super(in, length);

        if (length < 0)
        {
            throw new IllegalArgumentException("negative lengths not allowed");
        }

        this._originalLength = length;
        this._remaining = length;

        if (length == 0)
        {
            setParentEofDetect(true);
        }
    }

    int getRemaining()
    {
        return _remaining;
    }

    public int read()
        throws IOException
    {
        if (_remaining == 0)
        {
            return -1;
        }

        int b = _in.read();

        if (b < 0)
        {
            throw new EOFException("DEF length " + _originalLength + " object truncated by " + _remaining);
        }

        if (--_remaining == 0)
        {
            setParentEofDetect(true);
        }

        return b;
    }

    public int read(byte[] buf, int off, int len)
        throws IOException
    {
        if (_remaining == 0)
        {
            return -1;
        }

        int toRead = Math.min(len, _remaining);
        int numRead = _in.read(buf, off, toRead);

        if (numRead < 0)
        {
            throw new EOFException("DEF length " + _originalLength + " object truncated by " + _remaining);
        }

        if ((_remaining -= numRead) == 0)
        {
            setParentEofDetect(true);
        }

        return numRead;
    }

    byte[] toByteArray()
        throws IOException
    {
        if (_remaining == 0)
        {
            return EMPTY_BYTES;
        }

        // Read through this stream (not _in) so readLenBytesFully grows the buffer as bytes
        // arrive - avoiding the eager new byte[_remaining] that let a short crafted header drive a
        // heap-sized allocation before any data was read (CWE-789) - while read(byte[], int, int)
        // above keeps the _remaining / parent-EOF bookkeeping and reports a truncated stream with the
        // established "DEF length ... object truncated by ..." EOFException.
        return readLenBytesFully(this, _remaining);
    }

    // upstream's Streams.readLenBytesFully, kept private here
    private static byte[] readLenBytesFully(InputStream inStr, int len)
        throws IOException
    {
        if (len < 0)
        {
            throw new IllegalArgumentException("len cannot be negative");
        }

        // Start with a bounded buffer and grow it towards len (doubling) as bytes actually arrive,
        // reading straight into the result rather than allocating new byte[len] up front. A hostile
        // len therefore cannot drive a large allocation from a short input, and a small len still
        // allocates its exact size once.
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
}
