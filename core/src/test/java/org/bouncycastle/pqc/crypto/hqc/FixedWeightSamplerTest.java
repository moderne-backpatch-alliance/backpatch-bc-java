package org.bouncycastle.pqc.crypto.hqc;

import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.test.MethodOpcodes;

/**
 * HQCEngine.generateRandomFixedWeight samples the secret key supports, so its duplicate scan must
 * not branch on the support values: its only conditional branches are loop conditions.
 */
public class FixedWeightSamplerTest
    extends TestCase
{
    public void testSamplerBranchesOnlyOnLoops()
        throws Exception
    {
        List bodies = MethodOpcodes.findOpcodes(HQCEngine.class, "generateRandomFixedWeight");
        assertEquals(1, bodies.size());

        int[] ops = (int[])bodies.get(0);
        for (int i = 0; i != ops.length; i++)
        {
            int op = ops[i];
            boolean conditional = (op >= 0x99 && op <= 0xa6) || op == 0xc6 || op == 0xc7;
            // javac's loop conditions here: if_icmplt, if_icmpge, and iflt for the downward i >= 0 loop
            assertFalse("conditional branch opcode 0x" + Integer.toHexString(op),
                conditional && op != 0xa1 && op != 0xa2 && op != 0x9b);
        }
    }
}
