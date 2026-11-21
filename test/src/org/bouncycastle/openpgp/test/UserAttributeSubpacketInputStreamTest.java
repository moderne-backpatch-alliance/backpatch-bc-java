package org.bouncycastle.openpgp.test;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.bcpg.UserAttributeSubpacketInputStream;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression test for the unbounded user-attribute subpacket allocation: a crafted 4-octet length
 * header must be rejected against the absolute MAX_SUBPACKET_LEN cap before any body buffer is allocated.
 */
public class UserAttributeSubpacketInputStreamTest
    extends SimpleTest
{
    public String getName()
    {
        return "UserAttributeSubpacketInputStreamTest";
    }

    public void performTest()
        throws Exception
    {
        // A subpacket header declaring a 3 MiB body via the 4-octet length form, with no body.
        int claimed = 3 * 1024 * 1024;
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        bOut.write(0xFF);
        bOut.write((claimed >>> 24) & 0xFF);
        bOut.write((claimed >>> 16) & 0xFF);
        bOut.write((claimed >>> 8) & 0xFF);
        bOut.write(claimed & 0xFF);
        bOut.write(0x01); // subpacket type octet
        byte[] crafted = bOut.toByteArray();

        UserAttributeSubpacketInputStream sIn = new UserAttributeSubpacketInputStream(
            new BufferedInputStream(new ByteArrayInputStream(crafted)));

        try
        {
            sIn.readPacket();
            fail("oversized user attribute subpacket length accepted");
        }
        catch (IOException e)
        {
            if (!(e.getMessage() != null && e.getMessage().indexOf("exceeds max user attribute subpacket length") >= 0))
            {
                fail("unexpected message: " + e.getMessage());
            }
        }
    }

    public static void main(String[] args)
    {
        runTest(new UserAttributeSubpacketInputStreamTest());
    }
}
