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
 * (getEncoded, equals and hashCode all do) must not sort again.
 */
public class SetSortCacheTest
    extends SimpleTest
{
    private static int conversions;

    private static class CountingInteger
        extends ASN1Object
    {
        private final ASN1Integer value;

        CountingInteger(long value)
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

        isTrue("DER encoding changed between calls", Arrays.areEqual(first, second));

        ASN1EncodableVector sorted = new ASN1EncodableVector();
        for (int i = 1; i <= 16; i++)
        {
            sorted.add(new ASN1Integer(i));
        }
        isTrue("DER encoding not sorted", Arrays.areEqual(new DERSet(sorted).getEncoded(ASN1Encoding.DER), first));

        isTrue("second DER conversion sorted the SET again (" + firstConversions + " then " + secondConversions
            + " element conversions)", secondConversions < firstConversions);
    }

    public static void main(String[] args)
    {
        runTest(new SetSortCacheTest());
    }
}
