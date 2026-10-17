package org.bouncycastle.oer.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.OERInputStream;

/**
 * Bounds checks in the OER decoder against hostile input: recursion depth and SEQUENCE-OF element
 * count.
 */
public class OERInputStreamLimitTest
    extends TestCase
{
    /**
     * A nesting deeper than the decoder's cap must be rejected with a bounded IOException rather
     * than recursing until the JVM throws StackOverflowError. (The depth here, 320, comfortably
     * exceeds the 256 cap while staying well short of an actual stack overflow, so before the fix
     * the parse simply succeeded and this test failed - after the fix it throws.)
     */
    public void testNestingDepthBounded()
        throws Exception
    {
        OERDefinition.Builder b = OERDefinition.integer(0, 255);
        for (int i = 0; i < 320; i++)
        {
            b = OERDefinition.seq(b);
        }
        OERDefinition.Element schema = b.build();

        // 320 nested SEQUENCEs (each with a single explicit child consume no preamble bytes) then a
        // single one-byte INTEGER: a one-byte payload that drives 320 levels of recursive descent.
        byte[] payload = new byte[]{0x00};

        try
        {
            new OERInputStream(new ByteArrayInputStream(payload)).parse(schema);
            fail("over-deep nesting should be rejected");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().indexOf("nesting depth") >= 0);
        }
    }

    /**
     * A SEQUENCE-OF whose declared element count exceeds the bytes actually available must be
     * rejected before the parse loop, rather than looping ~count times allocating objects.
     */
    public void testSeqOfCountBounded()
        throws Exception
    {
        OERDefinition.Element schema = OERDefinition.seqof(OERDefinition.integer(0, 255)).build();

        // Count length-determinant 0x03 (count encoded in 3 bytes), count = 0x0186A0 (100000), and
        // then no element bytes at all - so the declared count vastly exceeds the remaining input.
        byte[] payload = new byte[]{0x03, 0x01, (byte)0x86, (byte)0xA0};

        try
        {
            new OERInputStream(new ByteArrayInputStream(payload)).parse(schema);
            fail("oversized SEQUENCE OF count should be rejected");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().indexOf("out of range") >= 0);
        }
    }
}
