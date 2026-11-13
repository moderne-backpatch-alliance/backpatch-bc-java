package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

/**
 * An unsorted SET sorts its elements for DER once and reuses that order: converting it to DER again
 * must not sort again.
 */
public class SetSortCacheTest
    extends SimpleTest
{
    private static int conversions;

    private static class CountingInteger
        extends ASN1Object
    {
        private final ASN1Integer value;

        CountingInteger(int value)
        {
            this.value = new ASN1Integer(value);
        }

        public ASN1Primitive toASN1Primitive()
        {
            conversions++;
            return value;
        }
    }

    public String getName()
    {
        return "SetSortCache";
    }

    public void performTest()
        throws Exception
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 16; i > 0; i--)
        {
            v.add(new CountingInteger(i));
        }

        ASN1Set set = new DLSet(v);

        conversions = 0;
        byte[] first = set.getEncoded(ASN1Encoding.DER);
        int firstConversions = conversions;

        conversions = 0;
        byte[] second = set.getEncoded(ASN1Encoding.DER);
        int secondConversions = conversions;

        check("DER encoding changed between calls", Arrays.areEqual(first, second));

        ASN1EncodableVector sorted = new ASN1EncodableVector();
        for (int i = 1; i <= 16; i++)
        {
            sorted.add(new ASN1Integer(i));
        }
        check("DER encoding not sorted", Arrays.areEqual(new DERSet(sorted).getEncoded(ASN1Encoding.DER), first));

        check("second DER conversion sorted the SET again (" + firstConversions + " then " + secondConversions
            + " element conversions)", secondConversions < firstConversions);

        // the DL form of a SET keeps the sort it has already done
        ASN1EncodableVector w = new ASN1EncodableVector();
        for (int i = 16; i > 0; i--)
        {
            w.add(new CountingInteger(i));
        }
        ASN1Set dlSet = new DLSet(w);
        byte[] der = dlSet.getEncoded(ASN1Encoding.DER);
        byte[] dl = dlSet.getEncoded(ASN1Encoding.DL);
        check("DL encoding is sorted", !Arrays.areEqual(der, dl));
        check("DER encoding changed after DL encoding", Arrays.areEqual(der, dlSet.getEncoded(ASN1Encoding.DER)));
    }

    private void check(String label, boolean ok)
    {
        if (!ok)
        {
            fail(label);
        }
    }

    public static void main(String[] args)
    {
        runTest(new SetSortCacheTest());
    }
}
