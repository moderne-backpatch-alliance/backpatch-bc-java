package org.bouncycastle.pqc.math.ntru;

import junit.framework.TestCase;
import org.bouncycastle.test.MethodOpcodes;

/**
 * NTRU's reductions of secret coefficients must compile to no integer division or remainder,
 * whose latency depends on the operand.
 */
public class PolynomialNoDivisionTest
    extends TestCase
{
    private static final int[] DIVISIONS = new int[]{
        MethodOpcodes.IDIV, MethodOpcodes.IREM, MethodOpcodes.LDIV, MethodOpcodes.LREM };

    public void testPolynomialMod3HasNoDivision()
        throws Exception
    {
        assertFalse(MethodOpcodes.containsAny(Polynomial.class, "mod3", DIVISIONS));
    }

    public void testPolynomialModQHasNoDivision()
        throws Exception
    {
        assertFalse(MethodOpcodes.containsAny(Polynomial.class, "modQ", DIVISIONS));
    }

    public void testSamplingMod3HasNoDivision()
        throws Exception
    {
        Class sampling = Class.forName("org.bouncycastle.pqc.crypto.ntru.NTRUSampling");

        assertFalse(MethodOpcodes.containsAny(sampling, "mod3", DIVISIONS));
    }

    public void testDivisionIsDetected()
        throws Exception
    {
        assertTrue(MethodOpcodes.containsAny(PolynomialNoDivisionTest.class, "remainder", DIVISIONS));
    }

    private static int remainder(int a, int b)
    {
        return a % b;
    }
}
