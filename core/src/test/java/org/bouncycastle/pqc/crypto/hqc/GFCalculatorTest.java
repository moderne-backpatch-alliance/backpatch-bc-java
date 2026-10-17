package org.bouncycastle.pqc.crypto.hqc;

import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.test.MethodOpcodes;

/**
 * HQC's GF(2^8) arithmetic must give the values of the field, and must not index a table by a
 * field element or branch on one: the operands are secret-derived.
 * <p>
 * The oracle builds log and exp tables by iterating the generator X over
 * GF(2)[X]/(X^8 + X^4 + X^3 + X^2 + 1), a different route from the carryless multiply under test
 * (adapted from upstream's GFTest for 1.78.1's GFCalculator).
 */
public class GFCalculatorTest
    extends TestCase
{
    private static final int MODULUS = 0x11D;
    private static final int ORDER = 255;

    private final int[] exp = new int[ORDER];
    private final int[] log = new int[256];

    public void setUp()
    {
        int x = 1;
        for (int i = 0; i < ORDER; ++i)
        {
            exp[i] = x;
            log[x] = i;

            int t = x << 1;
            if ((t & 0x100) != 0)
            {
                t ^= MODULUS;
            }
            x = t & 0xFF;
        }
    }

    public void testOracleIsTheExpectedField()
    {
        int[] expected = new int[]{1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38};
        for (int i = 0; i < expected.length; ++i)
        {
            assertEquals("exp[" + i + "]", expected[i], exp[i]);
        }

        boolean[] seen = new boolean[256];
        for (int i = 0; i < ORDER; ++i)
        {
            assertTrue("exp[" + i + "] is zero", exp[i] != 0);
            assertFalse("exp repeats " + exp[i], seen[exp[i]]);
            seen[exp[i]] = true;
            assertEquals("log(exp(" + i + "))", i, log[exp[i]]);
        }
    }

    private int oracleMul(int a, int b)
    {
        if (a == 0 || b == 0)
        {
            return 0;
        }
        return exp[(log[a] + log[b]) % ORDER];
    }

    private int oracleInv(int a)
    {
        if (a == 0)
        {
            return 0;
        }
        return exp[(ORDER - log[a]) % ORDER];
    }

    public void testMultAgainstOracle()
    {
        for (int a = 0; a < 256; ++a)
        {
            for (int b = 0; b < 256; ++b)
            {
                int r = GFCalculator.mult(a, b);
                assertEquals("mult(" + a + "," + b + ")", oracleMul(a, b), r);
                assertTrue("mult(" + a + "," + b + ") out of range: " + r, r >= 0 && r < 256);
            }
        }
    }

    public void testInverseAgainstOracle()
    {
        for (int a = 0; a < 256; ++a)
        {
            int r = GFCalculator.inverse(a);
            assertEquals("inverse(" + a + ")", oracleInv(a), r);
            assertTrue("inverse(" + a + ") out of range: " + r, r >= 0 && r < 256);
        }
    }

    public void testFieldLaws()
    {
        for (int a = 0; a < 256; ++a)
        {
            assertEquals("mult(" + a + ",1)", a, GFCalculator.mult(a, 1));
            if (a != 0)
            {
                assertEquals("a * inverse(a) for a=" + a, 1, GFCalculator.mult(a, GFCalculator.inverse(a)));
                assertEquals("inverse(inverse(a)) for a=" + a, a, GFCalculator.inverse(GFCalculator.inverse(a)));
            }
            for (int b = 0; b < 256; ++b)
            {
                assertEquals("commutativity " + a + "," + b, GFCalculator.mult(a, b), GFCalculator.mult(b, a));
            }
        }
    }

    public void testNoTableLookupOrDataBranch()
        throws Exception
    {
        String[] methods = new String[]{ "mult", "inverse", "reduce", "sqr" };
        for (int n = 0; n != methods.length; n++)
        {
            List bodies = MethodOpcodes.findOpcodes(GFCalculator.class, methods[n]);
            for (int m = 0; m != bodies.size(); m++)
            {
                int[] ops = (int[])bodies.get(m);
                for (int i = 0; i != ops.length; i++)
                {
                    int op = ops[i];
                    // iaload .. saload: an array element read
                    assertFalse(methods[n] + " reads an array (opcode 0x" + Integer.toHexString(op) + ")",
                        op >= 0x2e && op <= 0x35);
                    // conditional branches other than javac's loop conditions (if_icmplt, if_icmpge)
                    boolean conditional = (op >= 0x99 && op <= 0xa6) || op == 0xc6 || op == 0xc7;
                    assertFalse(methods[n] + " has conditional branch opcode 0x" + Integer.toHexString(op),
                        conditional && op != 0xa1 && op != 0xa2);
                }
            }
        }
    }
}
