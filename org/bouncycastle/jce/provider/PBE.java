package org.bouncycastle.jce.provider;

import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.PrivilegedAction;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S1ParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.DESParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public interface PBE
{
    //
    // PBE Based encryption constants - by default we do PKCS12 with SHA-1
    //
    static final int        MD5         = 0;
    static final int        SHA1        = 1;
    static final int        RIPEMD160   = 2;
    static final int        TIGER       = 3;
    static final int        SHA256      = 4;
    static final int        MD2         = 5;

    static final int        PKCS5S1     = 0;
    static final int        PKCS5S2     = 1;
    static final int        PKCS12      = 2;
    static final int        OPENSSL     = 3;

    /**
     * uses the appropriate mixer to generate the key and IV if necessary.
     */
    static class Util
    {
        static private PBEParametersGenerator makePBEGenerator(
            int                     type,
            int                     hash)
        {
            PBEParametersGenerator  generator;
    
            if (type == PKCS5S1)
            {
                switch (hash)
                {
                case MD2:
                    generator = new PKCS5S1ParametersGenerator(new MD2Digest());
                    break;
                case MD5:
                    generator = new PKCS5S1ParametersGenerator(new MD5Digest());
                    break;
                case SHA1:
                    generator = new PKCS5S1ParametersGenerator(new SHA1Digest());
                    break;
                default:
                    throw new IllegalStateException("PKCS5 scheme 1 only supports MD2, MD5 and SHA1.");
                }
            }
            else if (type == PKCS5S2)
            {
                generator = new PKCS5S2ParametersGenerator();
            }
            else if (type == PKCS12)
            {
                switch (hash)
                {
                case MD2:
                    generator = new PKCS12ParametersGenerator(new MD2Digest());
                    break;
                case MD5:
                    generator = new PKCS12ParametersGenerator(new MD5Digest());
                    break;
                case SHA1:
                    generator = new PKCS12ParametersGenerator(new SHA1Digest());
                    break;
                case RIPEMD160:
                    generator = new PKCS12ParametersGenerator(new RIPEMD160Digest());
                    break;
                case TIGER:
                    generator = new PKCS12ParametersGenerator(new TigerDigest());
                    break;
                case SHA256:
                    generator = new PKCS12ParametersGenerator(new SHA256Digest());
                    break;
                default:
                    throw new IllegalStateException("unknown digest scheme for PBE encryption.");
                }
            }
            else
            {
                generator = new OpenSSLPBEParametersGenerator();
            }
    
            return generator;
        }

        /**
         * Check an iteration count before it drives a derivation. The count usually arrives in an
         * unauthenticated parameters field (PBES1, PKCS#12 PBE) and the KDF runs before anything can be
         * verified, so an unbounded count is a CPU-exhaustion vector; the bound is
         * org.bouncycastle.pbe.max_iteration_count (default 10,000,000), as for PBKDF2.
         *
         * @param iterationCount the iteration count to check.
         * @return null if the count is acceptable, otherwise the reason it is not.
         */
        static String checkIterationCount(int iterationCount)
        {
            if (iterationCount < 0)
            {
                return "negative iteration count (" + iterationCount + ")";
            }

            int maxIT = getMaxIterationCount();
            if (iterationCount > maxIT)
            {
                return "iteration count (" + iterationCount + ") greater than " + maxIT;
            }

            return null;
        }

        /**
         * Check the iteration count of a PBEParameterSpec before a Cipher or Mac derives from it.
         *
         * @param spec the parameter spec; anything other than a PBEParameterSpec is ignored.
         * @throws InvalidAlgorithmParameterException if the iteration count is out of range.
         */
        static void checkIterationCount(AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException
        {
            if (spec instanceof PBEParameterSpec)
            {
                String problem = checkIterationCount(((PBEParameterSpec)spec).getIterationCount());
                if (problem != null)
                {
                    throw new InvalidAlgorithmParameterException(problem);
                }
            }
        }

        static void validateIterationCount(int iterationCount)
        {
            String problem = checkIterationCount(iterationCount);
            if (problem != null)
            {
                throw new IllegalArgumentException(problem);
            }
        }

        // 1.46 has no org.bouncycastle.util.Properties: upstream's property, read as a system property
        static int getMaxIterationCount()
        {
            String value = (String)AccessController.doPrivileged(new PrivilegedAction()
            {
                public Object run()
                {
                    return System.getProperty("org.bouncycastle.pbe.max_iteration_count");
                }
            });

            return (value != null) ? Integer.parseInt(value.trim()) : 10000000;
        }

        /**
         * construct a key and iv (if necessary) suitable for use with a 
         * Cipher.
         */
        static CipherParameters makePBEParameters(
            JCEPBEKey               pbeKey,
            AlgorithmParameterSpec  spec,
            String                  targetAlgorithm)
        {
            if ((spec == null) || !(spec instanceof PBEParameterSpec))
            {
                throw new IllegalArgumentException("Need a PBEParameter spec with a PBE key.");
            }
    
            PBEParameterSpec        pbeParam = (PBEParameterSpec)spec;
            validateIterationCount(pbeParam.getIterationCount());

            PBEParametersGenerator  generator = makePBEGenerator(pbeKey.getType(), pbeKey.getDigest());
            byte[]                  key = pbeKey.getEncoded();
            CipherParameters        param;
    
            if (pbeKey.shouldTryWrongPKCS12())
            {
                key = new byte[2];
            }
            
            generator.init(key, pbeParam.getSalt(), pbeParam.getIterationCount());

            if (pbeKey.getIvSize() != 0)
            {
                param = generator.generateDerivedParameters(pbeKey.getKeySize(), pbeKey.getIvSize());
            }
            else
            {
                param = generator.generateDerivedParameters(pbeKey.getKeySize());
            }

            if (targetAlgorithm.startsWith("DES"))
            {
                if (param instanceof ParametersWithIV)
                {
                    KeyParameter    kParam = (KeyParameter)((ParametersWithIV)param).getParameters();

                    DESParameters.setOddParity(kParam.getKey());
                }
                else
                {
                    KeyParameter    kParam = (KeyParameter)param;

                    DESParameters.setOddParity(kParam.getKey());
                }
            }

            for (int i = 0; i != key.length; i++)
            {
                key[i] = 0;
            }

            return param;
        }

        /**
         * generate a PBE based key suitable for a MAC algorithm, the
         * key size is chosen according the MAC size, or the hashing algorithm,
         * whichever is greater.
         */
        static CipherParameters makePBEMacParameters(
            JCEPBEKey               pbeKey,
            AlgorithmParameterSpec  spec)
        {
            if ((spec == null) || !(spec instanceof PBEParameterSpec))
            {
                throw new IllegalArgumentException("Need a PBEParameter spec with a PBE key.");
            }
    
            PBEParameterSpec        pbeParam = (PBEParameterSpec)spec;
            validateIterationCount(pbeParam.getIterationCount());

            PBEParametersGenerator  generator = makePBEGenerator(pbeKey.getType(), pbeKey.getDigest());
            byte[]                  key = pbeKey.getEncoded();
            CipherParameters        param;
    
            if (pbeKey.shouldTryWrongPKCS12())
            {
                key = new byte[2];
            }
            
            generator.init(key, pbeParam.getSalt(), pbeParam.getIterationCount());

            param = generator.generateDerivedMacParameters(pbeKey.getKeySize());
    
            for (int i = 0; i != key.length; i++)
            {
                key[i] = 0;
            }

            return param;
        }
    
        /**
         * construct a key and iv (if necessary) suitable for use with a 
         * Cipher.
         */
        static CipherParameters makePBEParameters(
            PBEKeySpec              keySpec,
            int                     type,
            int                     hash,
            int                     keySize,
            int                     ivSize)
        {    
            validateIterationCount(keySpec.getIterationCount());

            PBEParametersGenerator  generator = makePBEGenerator(type, hash);
            byte[]                  key;
            CipherParameters        param;
    
            if (type == PKCS12)
            {
                key = PBEParametersGenerator.PKCS12PasswordToBytes(keySpec.getPassword());
            }
            else
            {   
                key = PBEParametersGenerator.PKCS5PasswordToBytes(keySpec.getPassword());
            }
            
            generator.init(key, keySpec.getSalt(), keySpec.getIterationCount());
    
            if (ivSize != 0)
            {
                param = generator.generateDerivedParameters(keySize, ivSize);
            }
            else
            {
                param = generator.generateDerivedParameters(keySize);
            }
    
            for (int i = 0; i != key.length; i++)
            {
                key[i] = 0;
            }
    
            return param;
        }
    
        /**
         * generate a PBE based key suitable for a MAC algorithm, the
         * key size is chosen according the MAC size, or the hashing algorithm,
         * whichever is greater.
         */
        static CipherParameters makePBEMacParameters(
            PBEKeySpec              keySpec,
            int                     type,
            int                     hash,
            int                     keySize)
        {
            validateIterationCount(keySpec.getIterationCount());

            PBEParametersGenerator  generator = makePBEGenerator(type, hash);
            byte[]                  key;
            CipherParameters        param;
    
            if (type == PKCS12)
            {
                key = PBEParametersGenerator.PKCS12PasswordToBytes(keySpec.getPassword());
            }
            else
            {   
                key = PBEParametersGenerator.PKCS5PasswordToBytes(keySpec.getPassword());
            }
            
            generator.init(key, keySpec.getSalt(), keySpec.getIterationCount());
    
            param = generator.generateDerivedMacParameters(keySize);
    
            for (int i = 0; i != key.length; i++)
            {
                key[i] = 0;
            }
    
            return param;
        }
    }
}
