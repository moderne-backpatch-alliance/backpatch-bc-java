package org.bouncycastle.pqc.crypto.frodo;

import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.test.MethodOpcodes;

/**
 * FrodoKEM's error sampling and its decapsulation re-encryption check run on secret values, so
 * they must not branch on them. Sampling results must be unchanged.
 */
public class FrodoConstantTimeTest
    extends TestCase
{
    // FrodoKEM-640, -976 and -1344 noise CDF tables (FrodoParameters)
    private static final short[][] CDF_TABLES = new short[][]{
        {4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767},
        {5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767},
        {9142, 23462, 30338, 32361, 32725, 32765, 32767}};

    private static final int IF_ICMPLT = 0xa1;
    private static final int IF_ICMPGE = 0xa2;
    private static final int IRETURN = 0xac;

    public void testSamplingMatchesSpecification()
    {
        short[] r = new short[1 << 16];
        for (int i = 0; i != r.length; i++)
        {
            r[i] = (short)i;
        }

        for (int t = 0; t != CDF_TABLES.length; t++)
        {
            short[] s = new short[r.length];
            Noise.sample(CDF_TABLES[t], r, 0, s);

            for (int i = 0; i != r.length; i++)
            {
                assertEquals("table " + t + " r " + i, reference(CDF_TABLES[t], r[i]), s[i]);
            }
        }
    }

    public void testSamplingHasOnlyLoopBranches()
        throws Exception
    {
        checkOnlyLoopBranches(Noise.class, "sample");
        checkOnlyLoopBranches(FrodoEngine.class, "sample");
        checkOnlyLoopBranches(FrodoEngine.class, "sample_matrix");
    }

    public void testCtverifyIsBranchFree()
        throws Exception
    {
        checkOnlyLoopBranches(FrodoEngine.class, "ctverify");

        List methods = MethodOpcodes.findOpcodes(FrodoEngine.class, "ctverify");
        assertEquals(1, methods.size());
        int returns = 0;
        int[] ops = (int[])methods.get(0);
        for (int i = 0; i != ops.length; i++)
        {
            if (ops[i] == IRETURN)
            {
                returns++;
            }
        }
        assertEquals("ctverify return instructions", 1, returns);
    }

    // conditional branches other than a loop's own exit or back edge (javac's if_icmpge / if_icmplt)
    private static void checkOnlyLoopBranches(Class cls, String name)
        throws Exception
    {
        List methods = MethodOpcodes.findOpcodes(cls, name);
        for (int m = 0; m != methods.size(); m++)
        {
            int[] ops = (int[])methods.get(m);
            for (int i = 0; i != ops.length; i++)
            {
                int op = ops[i];
                boolean conditional = (op >= 0x99 && op <= 0xa6) || op == 0xc6 || op == 0xc7 || op == 0xaa || op == 0xab;
                if (conditional && op != IF_ICMPLT && op != IF_ICMPGE)
                {
                    fail(cls.getName() + "." + name + " has conditional branch opcode 0x" + Integer.toHexString(op));
                }
            }
        }
    }

    // FrodoKEM specification, Algorithm 5 (Frodo.Sample), as the branching code computed it
    private static short reference(short[] cdf, short r)
    {
        int t = (r & 0xffff) >>> 1;
        int e = 0;
        for (int z = 0; z < cdf.length; z++)
        {
            if (t > cdf[z])
            {
                e++;
            }
        }
        if (((r & 0xffff) & 1) == 1)
        {
            e = -e;
        }
        return (short)e;
    }
}
