package org.bouncycastle.cms.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CCMParameters;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSTagLengthException;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.operator.GenericKey;

class CMSUtils
{
    static CipherParameters getBcKey(GenericKey key)
    {
        if (key.getRepresentation() instanceof CipherParameters)
        {
            return (CipherParameters)key.getRepresentation();
        }

        if (key.getRepresentation() instanceof byte[])
        {
            return new KeyParameter((byte[])key.getRepresentation());
        }

        throw new IllegalArgumentException("unknown generic key type");
    }

    /**
     * Refuse an AEAD content algorithm whose authentication tag is shorter than the configured
     * minimum. A no-op when no minimum is set or when the content algorithm is not AEAD.
     */
    static void checkTagSize(AlgorithmIdentifier contentAlgorithm, int minimumTagSizeInBits)
        throws CMSTagLengthException
    {
        if (minimumTagSizeInBits > 0)
        {
            int macLenOctets = getAEADMacLength(contentAlgorithm);

            if (macLenOctets >= 0 && macLenOctets * 8 < minimumTagSizeInBits)
            {
                throw new CMSTagLengthException("AEAD tag size " + (macLenOctets * 8)
                    + " bits below required minimum " + minimumTagSizeInBits + " bits");
            }
        }
    }

    // the AEAD tag length carried in AuthEnvelopedData's content algorithm, or -1 if not AEAD
    private static int getAEADMacLength(AlgorithmIdentifier encAlgId)
    {
        ASN1ObjectIdentifier algorithm = encAlgId.getAlgorithm();

        if (CMSAlgorithm.AES128_GCM.equals(algorithm)
            || CMSAlgorithm.AES192_GCM.equals(algorithm)
            || CMSAlgorithm.AES256_GCM.equals(algorithm))
        {
            return GCMParameters.getInstance(encAlgId.getParameters()).getIcvLen();
        }
        if (CMSAlgorithm.AES128_CCM.equals(algorithm)
            || CMSAlgorithm.AES192_CCM.equals(algorithm)
            || CMSAlgorithm.AES256_CCM.equals(algorithm))
        {
            return CCMParameters.getInstance(encAlgId.getParameters()).getIcvLen();
        }

        return -1;
    }
}
