package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERExternal;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * DER encoding a SET nested in an EXTERNAL, and so on, grows with the depth, not exponentially, and
 * the encoding itself does not change.
 */
public class ExternalNestingTest
    extends SimpleTest
{
    private static long conversions;

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
        return "ExternalNesting";
    }

    private ASN1Encodable nest(int depth)
    {
        ASN1EncodableVector set = new ASN1EncodableVector();
        if (depth == 0)
        {
            set.add(new CountingInteger(2));
            set.add(new CountingInteger(1));
            return new DLSet(set);
        }
        set.add(nest(depth - 1));
        set.add(new CountingInteger(depth));

        ASN1EncodableVector external = new ASN1EncodableVector();
        external.add(new ASN1ObjectIdentifier("1.2.3"));
        external.add(new DERTaggedObject(true, 0, new DLSet(set)));
        return new DERExternal(external);
    }

    private long work(int depth)
        throws Exception
    {
        ASN1Object nested = (ASN1Object)nest(depth);
        conversions = 0;
        nested.getEncoded(ASN1Encoding.DER);
        return conversions;
    }

    public void performTest()
        throws Exception
    {
        // as this class encodes at the 1.47 baseline
        byte[] expected = Hex.decode(EXPECTED);
        byte[] encoded = ((ASN1Object)nest(2)).getEncoded(ASN1Encoding.DER);
        if (!Arrays.areEqual(expected, encoded))
        {
            fail("encoding changed: " + new String(Hex.encode(encoded)));
        }
        if (!Arrays.areEqual(expected, ((ASN1Object)nest(2)).getEncoded()))
        {
            fail("BER form of the EXTERNAL changed");
        }

        long shallow = work(4);
        long deep = work(8);
        if (deep > shallow * 8)
        {
            fail("work grew from " + shallow + " at depth 4 to " + deep + " at depth 8");
        }
    }

    private static final String EXPECTED = "282006022a03a01a3118020102281306022a03a00d310b0201013106020101020102";

    public static void main(String[] args)
    {
        runTest(new ExternalNestingTest());
    }
}
