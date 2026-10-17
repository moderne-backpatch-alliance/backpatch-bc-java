package org.bouncycastle.pqc.crypto.hqc;

/**
 * Arithmetic in GF(2^8) = GF(2)[X]/(X^8 + X^4 + X^3 + X^2 + 1), the field underlying HQC's
 * Reed-Solomon code. Table-free and branch-free: the operands are secret-derived, so neither a
 * table indexed by a field element nor a data-dependent branch may be used here.
 */
class GFCalculator
{
    private static final int MODULUS = 0x11D;

    // a carryless product (degree at most 14) mod MODULUS; each reduction step is applied by mask
    private static int reduce(int x)
    {
        for (int i = 14; i >= 8; --i)
        {
            int m = -((x >>> i) & 1);
            x ^= m & (MODULUS << (i - 8));
        }

        return x & 0xFF;
    }

    static int mult(int a, int b)
    {
        int p = 0;
        for (int i = 0; i < 8; ++i)
        {
            int m = -((b >>> i) & 1);
            p ^= m & (a << i);
        }

        return reduce(p);
    }

    private static int sqr(int a)
    {
        int x = a;
        x = (x | (x << 4)) & 0x0F0F;
        x = (x | (x << 2)) & 0x3333;
        x = (x | (x << 1)) & 0x5555;

        return reduce(x);
    }

    static int inverse(int a)
    {
        // a^254 = a^-1 for a != 0, and 0 for a == 0
        int a2 = sqr(a);
        int a3 = mult(a2, a);
        int a6 = sqr(a3);
        int a7 = mult(a6, a);
        int a14 = sqr(a7);
        int a15 = mult(a14, a);
        int a30 = sqr(a15);
        int a31 = mult(a30, a);
        int a62 = sqr(a31);
        int a63 = mult(a62, a);
        int a126 = sqr(a63);
        int a127 = mult(a126, a);

        return sqr(a127);
    }
}
