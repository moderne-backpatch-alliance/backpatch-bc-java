package org.bouncycastle.asn1.test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Exception;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.encoders.Hex;

public class ASN1SequenceParserTest 
    extends TestCase 
{
    private static final byte[] seqData = Hex.decode("3006020100060129");
    private static final byte[] nestedSeqData = Hex.decode("300b0201000601293003020101");
    private static final byte[] expTagSeqData = Hex.decode("a1083006020100060129");
    private static final byte[] implTagSeqData = Hex.decode("a106020100060129");
    private static final byte[] nestedSeqExpTagData = Hex.decode("300d020100060129a1053003020101");
    private static final byte[] nestedSeqImpTagData = Hex.decode("300b020100060129a103020101");
    
    private static final byte[] berSeqData = Hex.decode("30800201000601290000");
    private static final byte[] berDERNestedSeqData = Hex.decode("308002010006012930030201010000");
    private static final byte[] berNestedSeqData = Hex.decode("3080020100060129308002010100000000");
    private static final byte[] berExpTagSeqData = Hex.decode("a180308002010006012900000000");

    private static final byte[] berSeqWithDERNullData = Hex.decode("308005000201000601290000");

    public void testDERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator  seqGen = new DERSequenceGenerator(bOut);
       
       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));
       
       seqGen.close();

       assertTrue("basic DER writing test failed.", Arrays.equals(seqData, bOut.toByteArray()));
    }
 
    public void testNestedDERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator seqGen1 = new DERSequenceGenerator(bOut);
       
       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));
       
       DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream());
       
       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested DER writing test failed.", Arrays.equals(nestedSeqData, bOut.toByteArray()));
    }

    public void testDERExplicitTaggedSequenceWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator  seqGen = new DERSequenceGenerator(bOut, 1, true);
       
       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));
       
       seqGen.close();

       assertTrue("explicit tag writing test failed.", Arrays.equals(expTagSeqData, bOut.toByteArray()));
    }
    
    public void testDERImplicitTaggedSequenceWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator  seqGen = new DERSequenceGenerator(bOut, 1, false);
       
       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));
       
       seqGen.close();

       assertTrue("implicit tag writing test failed.", Arrays.equals(implTagSeqData, bOut.toByteArray()));
    }
    
    public void testNestedExplicitTagDERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator  seqGen1 = new DERSequenceGenerator(bOut);
       
       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));
       
       DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream(), 1, true);
       
       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested explicit tagged DER writing test failed.", Arrays.equals(nestedSeqExpTagData, bOut.toByteArray()));
    }
    
    public void testNestedImplicitTagDERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator  seqGen1 = new DERSequenceGenerator(bOut);
       
       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));
       
       DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream(), 1, false);
       
       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested implicit tagged DER writing test failed.", Arrays.equals(nestedSeqImpTagData, bOut.toByteArray()));
    }
    
    public void testBERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BERSequenceGenerator  seqGen = new BERSequenceGenerator(bOut);
       
       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));
       
       seqGen.close();
       
       assertTrue("basic BER writing test failed.", Arrays.equals(berSeqData, bOut.toByteArray()));
    }

    public void testNestedBERDERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BERSequenceGenerator seqGen1 = new BERSequenceGenerator(bOut);
       
       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));
       
       DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream());
       
       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested BER/DER writing test failed.", Arrays.equals(berDERNestedSeqData, bOut.toByteArray()));
    }
    
    public void testNestedBERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BERSequenceGenerator  seqGen1 = new BERSequenceGenerator(bOut);
       
       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));
       
       BERSequenceGenerator seqGen2 = new BERSequenceGenerator(seqGen1.getRawOutputStream());
       
       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested BER writing test failed.", Arrays.equals(berNestedSeqData, bOut.toByteArray()));
    }
    
    public void testDERReading()
        throws Exception
    {
        ASN1StreamParser aIn = new ASN1StreamParser(seqData);
        
        ASN1SequenceParser    seq = (ASN1SequenceParser)aIn.readObject();
        Object          o;
        int             count = 0;
        
        assertNotNull("null sequence returned", seq);
        
        while ((o = seq.readObject()) != null)
        {
            switch (count)
            {
            case 0:
                assertTrue(o instanceof ASN1Integer);
                break;
            case 1:
                assertTrue(o instanceof ASN1ObjectIdentifier);
                break;
            }
            count++;
        }
        
        assertEquals("wrong number of objects in sequence", 2, count);
    }

    private void testNestedReading(
        byte[] data)
        throws Exception
    {
        ASN1StreamParser aIn = new ASN1StreamParser(data);
        
        ASN1SequenceParser seq = (ASN1SequenceParser)aIn.readObject();
        Object          o;
        int             count = 0;
        
        assertNotNull("null sequence returned", seq);
        
        while ((o = seq.readObject()) != null)
        {
            switch (count)
            {
            case 0:
                assertTrue(o instanceof ASN1Integer);
                break;
            case 1:
                assertTrue(o instanceof ASN1ObjectIdentifier);
                break;
            case 2:
                assertTrue(o instanceof ASN1SequenceParser);
                
                ASN1SequenceParser s = (ASN1SequenceParser)o;

                // NB: Must exhaust the nested parser
                while (s.readObject() != null)
                {
                    // Nothing
                }

                break;
            }
            count++;
        }
        
        assertEquals("wrong number of objects in sequence", 3, count);
    }
    
    public void testNestedDERReading()
        throws Exception
    {
        testNestedReading(nestedSeqData);
    }
    
    public void testBERReading()
        throws Exception
    {
        ASN1StreamParser aIn = new ASN1StreamParser(berSeqData);
        
        ASN1SequenceParser    seq = (ASN1SequenceParser)aIn.readObject();
        Object          o;
        int             count = 0;
        
        assertNotNull("null sequence returned", seq);
        
        while ((o = seq.readObject()) != null)
        {
            switch (count)
            {
            case 0:
                assertTrue(o instanceof ASN1Integer);
                break;
            case 1:
                assertTrue(o instanceof ASN1ObjectIdentifier);
                break;
            }
            count++;
        }
        
        assertEquals("wrong number of objects in sequence", 2, count);
    }
    
    public void testNestedBERDERReading()
        throws Exception
    {
        testNestedReading(berDERNestedSeqData);
    }
    
    public void testNestedBERReading()
        throws Exception
    {
        testNestedReading(berNestedSeqData);
    }
    
    public void testBERExplicitTaggedSequenceWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BERSequenceGenerator  seqGen = new BERSequenceGenerator(bOut, 1, true);
       
       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));
       
       seqGen.close();
      
       assertTrue("explicit BER tag writing test failed.", Arrays.equals(berExpTagSeqData, bOut.toByteArray()));
    }

    public void testHeavilyDLNestedSequence()
        throws Exception
    {
        try
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(new ASN1InputStream(findTestResource("asn1", "nested_seq.der")).readObject());
            fail("no exception");
        }
        catch (ASN1Exception e)
        {
            assertEquals("maximum nested construction level reached", e.getMessage());
        }
    }

    public void testHeavilyBERNestedSequence()
        throws Exception
    {
        try
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(new ASN1InputStream(findTestResource("asn1", "nested_seq_indef.ber")).readObject());
            fail("no exception");
        }
        catch (ASN1Exception e)
        {
            assertEquals("maximum nested construction level reached", e.getMessage());
        }
    }

    public void testHeavilyLazyNestedSequence()
        throws Exception
    {
        // Deeply nested SEQUENCE { SEQUENCE { ... } }, well past the default max_cons_depth (64)
        // but shallow enough that a whole-tree walk would not itself overflow the Java stack if the
        // guard were absent -- so this proves the guard is enforced, not merely that we crash.
        ASN1Encodable node = new DERSequence();
        for (int i = 0; i < 256; i++)
        {
            node = new DERSequence(node);
        }
        byte[] der = node.toASN1Primitive().getEncoded(ASN1Encoding.DER);

        // The lazy parse succeeds shallowly (only the outermost level is decoded eagerly).
        ASN1Primitive parsed = new ASN1InputStream(der, true).readObject();

        // Forcing the whole tree (hashCode walks every element) must hit the same nested-construction
        // limit the eager path enforces, raising an ASN1Exception rather than a StackOverflowError.
        try
        {
            parsed.hashCode();
            fail("nested construction depth limit not enforced on lazy parse");
        }
        catch (ASN1ParsingException e)
        {
            assertEquals("maximum nested construction level reached", e.getCause().getMessage());
        }
    }

    private static InputStream findTestResource(String homeDir, String fileName)
        throws IOException
    {
        // test data lives in core/src/test/data here (bc.test.data.home), not in bc-test-data
        String dataHome = System.getProperty("bc.test.data.home", "core/src/test/data");

        return new FileInputStream(new File(new File(dataHome, homeDir), fileName));
    }

    public void testDefaultMaxConsDepth()
        throws Exception
    {
        new ASN1InputStream(dlNestedSequence(64)).readObject();
        new ASN1InputStream(dlNestedSequence(64), true).readObject().hashCode();
        new ASN1InputStream(berNestedSequence(64)).readObject();

        try
        {
            new ASN1InputStream(dlNestedSequence(65)).readObject();
            fail("default nested construction depth limit not enforced");
        }
        catch (ASN1Exception e)
        {
            assertEquals("maximum nested construction level reached", e.getMessage());
        }
    }

    public void testMaxConsDepthProperty()
        throws Exception
    {
        byte[] dlAtLimit = dlNestedSequence(8);
        byte[] dlOverLimit = dlNestedSequence(9);
        byte[] berAtLimit = berNestedSequence(8);
        byte[] berOverLimit = berNestedSequence(9);

        System.setProperty("org.bouncycastle.asn1.max_cons_depth", "8");
        try
        {
            new ASN1InputStream(dlAtLimit).readObject();
            new ASN1InputStream(dlAtLimit, true).readObject().hashCode();
            new ASN1InputStream(berAtLimit).readObject();

            try
            {
                new ASN1InputStream(dlOverLimit).readObject();
                fail("nested construction depth limit not enforced on DL parse");
            }
            catch (ASN1Exception e)
            {
                assertEquals("maximum nested construction level reached", e.getMessage());
            }

            ASN1Primitive lazy = new ASN1InputStream(dlOverLimit, true).readObject();
            try
            {
                lazy.hashCode();
                fail("nested construction depth limit not enforced on lazy parse");
            }
            catch (ASN1ParsingException e)
            {
                assertEquals("maximum nested construction level reached", e.getCause().getMessage());
            }

            try
            {
                new ASN1InputStream(berOverLimit).readObject();
                fail("nested construction depth limit not enforced on BER parse");
            }
            catch (ASN1Exception e)
            {
                assertEquals("maximum nested construction level reached", e.getMessage());
            }
        }
        finally
        {
            System.clearProperty("org.bouncycastle.asn1.max_cons_depth");
        }
    }

    public void testMaxConsDepthTaggedProperty()
        throws Exception
    {
        byte[] atLimit = dlNestedTagged(8);
        byte[] overLimit = dlNestedTagged(9);

        System.setProperty("org.bouncycastle.asn1.max_cons_depth", "8");
        try
        {
            new ASN1InputStream(atLimit).readObject();

            try
            {
                new ASN1InputStream(overLimit).readObject();
                fail("nested construction depth limit not enforced on tagged objects");
            }
            catch (ASN1Exception e)
            {
                assertEquals("maximum nested construction level reached", e.getMessage());
            }
        }
        finally
        {
            System.clearProperty("org.bouncycastle.asn1.max_cons_depth");
        }
    }

    private static byte[] dlNestedTagged(int depth)
        throws IOException
    {
        ASN1Encodable node = new DEROctetString(new byte[1]);
        for (int i = 0; i < depth; i++)
        {
            node = new DERTaggedObject(true, 0, node);
        }
        return node.toASN1Primitive().getEncoded(ASN1Encoding.DER);
    }

    private static byte[] dlNestedSequence(int depth)
        throws IOException
    {
        ASN1Encodable node = new DERSequence();
        for (int i = 0; i < depth; i++)
        {
            node = new DERSequence(node);
        }
        return node.toASN1Primitive().getEncoded(ASN1Encoding.DER);
    }

    private static byte[] berNestedSequence(int depth)
    {
        // depth headers of 30 80, followed by depth end-of-contents octet pairs (the zeroed tail)
        byte[] data = new byte[depth * 4];
        for (int i = 0; i < depth; i++)
        {
            data[2 * i] = 0x30;
            data[2 * i + 1] = (byte)0x80;
        }
        return data;
    }

    public void testSequenceWithDERNullReading()
        throws Exception
    {
        testParseWithNull(berSeqWithDERNullData);
    }

    private void testParseWithNull(byte[] data)
        throws IOException
    {
        ASN1StreamParser aIn = new ASN1StreamParser(data);
        ASN1SequenceParser seq = (ASN1SequenceParser)aIn.readObject();
        Object          o;
        int             count = 0;

        assertNotNull("null sequence returned", seq);

        while ((o = seq.readObject()) != null)
        {
            switch (count)
            {
            case 0:
                assertTrue(o instanceof ASN1Null);
                break;
            case 1:
                assertTrue(o instanceof ASN1Integer);
                break;
            case 2:
                assertTrue(o instanceof ASN1ObjectIdentifier);
                break;
            }
            count++;
        }

        assertEquals("wrong number of objects in sequence", 3, count);
    }

    public static Test suite()
    {
        return new TestSuite(ASN1SequenceParserTest.class);
    }
}
