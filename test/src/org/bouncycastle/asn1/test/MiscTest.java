package org.bouncycastle.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.misc.CAST5CBCParameters;
import org.bouncycastle.asn1.misc.IDEACBCPar;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.misc.NetscapeRevocationURL;
import org.bouncycastle.asn1.misc.VerisignCzagExtension;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class MiscTest
    implements Test
{
    private boolean isSameAs(
        byte[]  a,
        byte[]  b)
    {
        if (a.length != b.length)
        {
            return false;
        }
        
        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }
        
        return true;
    }
    
    private void isTrue(String message, boolean value)
    {
        if (!value)
        {
            throw new IllegalStateException(message);
        }
    }

    public void derIntegerTest()
        throws Exception
    {
        try
        {
            new DERInteger(new byte[] { 0, 0, 0, 1});
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong exc", "malformed integer".equals(e.getMessage()));
        }

        try
        {
            new DERInteger(new byte[] {(byte)0xff, (byte)0x80, 0, 1});
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong exc", "malformed integer".equals(e.getMessage()));
        }

        try
        {
            new DEREnumerated(new byte[] { 0, 0, 0, 1});
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong exc", "malformed enumerated".equals(e.getMessage()));
        }

        try
        {
            new DEREnumerated(new byte[] {(byte)0xff, (byte)0x80, 0, 1});
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong exc", "malformed enumerated".equals(e.getMessage()));
        }
    }

    public TestResult perform()
    {
        byte[]  testIv = { 1, 2, 3, 4, 5, 6, 7, 8 };
        
        ASN1Encodable[]     values = {
            new CAST5CBCParameters(testIv, 128), 
            new NetscapeCertType(NetscapeCertType.smime),    
            new VerisignCzagExtension(new DERIA5String("hello")),
            new IDEACBCPar(testIv),        
            new NetscapeRevocationURL(new DERIA5String("http://test"))
        };
        
        byte[] data = Base64.decode("MA4ECAECAwQFBgcIAgIAgAMCBSAWBWhlbGxvMAoECAECAwQFBgcIFgtodHRwOi8vdGVzdA==");
        
        try
        {
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            ASN1OutputStream        aOut = new ASN1OutputStream(bOut);
            
            for (int i = 0; i != values.length; i++)
            {
                aOut.writeObject(values[i]);
            }
            
            ASN1Primitive[] readValues = new ASN1Primitive[values.length];
            
            if (!isSameAs(bOut.toByteArray(), data))
            {
                return new SimpleTestResult(false, getName() + ": Failed data check");
            }
            
            ByteArrayInputStream    bIn = new ByteArrayInputStream(bOut.toByteArray());
            ASN1InputStream         aIn = new ASN1InputStream(bIn);
            
            for (int i = 0; i != values.length; i++)
            {
                ASN1Primitive   o = aIn.readObject();
                if (!values[i].equals(o))
                {
                    return new SimpleTestResult(false, getName() + ": Failed equality test for " + o);
                }
                
                if (o.hashCode() != values[i].hashCode())
                {
                    return new SimpleTestResult(false, getName() + ": Failed hashCode test for " + o);
                }
            }
            
            derIntegerTest();

            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Failed - exception " + e.toString(), e);
        }
    }

    public String getName()
    {
        return "Misc";
    }

    public static void main(
        String[] args)
    {
        MiscTest    test = new MiscTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
