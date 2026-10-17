package org.bouncycastle.test;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads the bytecode of a class's methods, so tests can check which instructions a
 * constant-time method compiles to (for example that it contains no integer division).
 */
public class MethodOpcodes
{
    public static final int IDIV = 0x6c;
    public static final int LDIV = 0x6d;
    public static final int IREM = 0x70;
    public static final int LREM = 0x71;

    /**
     * Return the opcodes of every method of the class called name, in order, one list per method
     * with that name (overloads included).
     */
    public static List findOpcodes(Class cls, String name)
        throws IOException
    {
        String resource = "/" + cls.getName().replace('.', '/') + ".class";
        InputStream in = cls.getResourceAsStream(resource);
        if (in == null)
        {
            throw new IOException("class file not found: " + resource);
        }

        try
        {
            return parse(new DataInputStream(in), name);
        }
        finally
        {
            in.close();
        }
    }

    /**
     * Return true if any method of the class called name contains one of the given opcodes.
     */
    public static boolean containsAny(Class cls, String name, int[] opcodes)
        throws IOException
    {
        List methods = findOpcodes(cls, name);
        if (methods.isEmpty())
        {
            throw new IOException("no method " + name + " in " + cls.getName());
        }
        for (int i = 0; i != methods.size(); i++)
        {
            int[] ops = (int[])methods.get(i);
            for (int j = 0; j != ops.length; j++)
            {
                for (int k = 0; k != opcodes.length; k++)
                {
                    if (ops[j] == opcodes[k])
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static List parse(DataInputStream dIn, String name)
        throws IOException
    {
        if (dIn.readInt() != 0xCAFEBABE)
        {
            throw new IOException("not a class file");
        }
        dIn.readUnsignedShort();
        dIn.readUnsignedShort();

        int cpCount = dIn.readUnsignedShort();
        String[] utf8 = new String[cpCount];
        for (int i = 1; i < cpCount; i++)
        {
            int tag = dIn.readUnsignedByte();
            switch (tag)
            {
            case 1:
                utf8[i] = dIn.readUTF();
                break;
            case 3:
            case 4:
            case 9:
            case 10:
            case 11:
            case 12:
            case 17:
            case 18:
                dIn.readInt();
                break;
            case 5:
            case 6:
                dIn.readLong();
                i++;
                break;
            case 7:
            case 8:
            case 16:
            case 19:
            case 20:
                dIn.readUnsignedShort();
                break;
            case 15:
                dIn.readUnsignedByte();
                dIn.readUnsignedShort();
                break;
            default:
                throw new IOException("unknown constant pool tag " + tag);
            }
        }

        dIn.readUnsignedShort();
        dIn.readUnsignedShort();
        dIn.readUnsignedShort();
        skip(dIn, dIn.readUnsignedShort() * 2);

        int fieldCount = dIn.readUnsignedShort();
        for (int i = 0; i != fieldCount; i++)
        {
            skip(dIn, 6);
            skipAttributes(dIn);
        }

        List result = new ArrayList();
        int methodCount = dIn.readUnsignedShort();
        for (int i = 0; i != methodCount; i++)
        {
            dIn.readUnsignedShort();
            String methodName = utf8[dIn.readUnsignedShort()];
            dIn.readUnsignedShort();
            int attrCount = dIn.readUnsignedShort();
            for (int a = 0; a != attrCount; a++)
            {
                String attrName = utf8[dIn.readUnsignedShort()];
                int len = dIn.readInt();
                if ("Code".equals(attrName) && name.equals(methodName))
                {
                    dIn.readUnsignedShort();
                    dIn.readUnsignedShort();
                    byte[] code = new byte[dIn.readInt()];
                    dIn.readFully(code);
                    skip(dIn, len - 8 - code.length);
                    result.add(decode(code));
                }
                else
                {
                    skip(dIn, len);
                }
            }
        }
        return result;
    }

    private static void skipAttributes(DataInputStream dIn)
        throws IOException
    {
        int count = dIn.readUnsignedShort();
        for (int i = 0; i != count; i++)
        {
            dIn.readUnsignedShort();
            skip(dIn, dIn.readInt());
        }
    }

    private static void skip(DataInputStream dIn, int len)
        throws IOException
    {
        while (len > 0)
        {
            int n = dIn.skipBytes(len);
            if (n <= 0)
            {
                throw new IOException("truncated class file");
            }
            len -= n;
        }
    }

    private static int[] decode(byte[] code)
    {
        int[] ops = new int[code.length];
        int count = 0;
        int pc = 0;
        while (pc < code.length)
        {
            int op = code[pc] & 0xff;
            ops[count++] = op;
            pc += length(code, pc, op);
        }
        int[] rv = new int[count];
        System.arraycopy(ops, 0, rv, 0, count);
        return rv;
    }

    private static int length(byte[] code, int pc, int op)
    {
        switch (op)
        {
        case 0x10: case 0x12: case 0x15: case 0x16: case 0x17: case 0x18: case 0x19:
        case 0x36: case 0x37: case 0x38: case 0x39: case 0x3a: case 0xa9: case 0xbc:
            return 2;
        case 0x11: case 0x13: case 0x14: case 0x84: case 0xb2: case 0xb3: case 0xb4: case 0xb5:
        case 0xb6: case 0xb7: case 0xb8: case 0xbb: case 0xbd: case 0xc0: case 0xc1: case 0xc6:
        case 0xc7:
            return 3;
        case 0xc5:
            return 4;
        case 0xb9: case 0xba: case 0xc8: case 0xc9:
            return 5;
        case 0xc4:
            return ((code[pc + 1] & 0xff) == 0x84) ? 6 : 4;
        case 0xaa:
        {
            int p = (pc + 4) & ~3;
            int low = readInt(code, p + 4);
            int high = readInt(code, p + 8);
            return p + 12 + (high - low + 1) * 4 - pc;
        }
        case 0xab:
        {
            int p = (pc + 4) & ~3;
            int pairs = readInt(code, p + 4);
            return p + 8 + pairs * 8 - pc;
        }
        default:
            if (op >= 0x99 && op <= 0xa8)
            {
                return 3;
            }
            return 1;
        }
    }

    private static int readInt(byte[] b, int off)
    {
        return (b[off] << 24) | ((b[off + 1] & 0xff) << 16) | ((b[off + 2] & 0xff) << 8) | (b[off + 3] & 0xff);
    }
}
