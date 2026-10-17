package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;

/**
 * a Diffie-Hellman key exchange engine.
 * <p>
 * note: This uses MTI/A0 key agreement in order to make the key agreement
 * secure against passive attacks. If you're doing Diffie-Hellman and both
 * parties have long term public keys you should look at using this. For
 * further information have a look at RFC 2631.
 * <p>
 * It's possible to extend this to more than two parties as well, for the moment
 * that is left as an exercise for the reader.
 */
public class DHAgreement
{
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private DHPrivateKeyParameters  key;
    private DHParameters            dhParams;
    private BigInteger              privateValue;
    private SecureRandom            random;

    public void init(
        CipherParameters    param)
    {
        AsymmetricKeyParameter  kParam;

        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom    rParam = (ParametersWithRandom)param;

            this.random = rParam.getRandom();
            kParam = (AsymmetricKeyParameter)rParam.getParameters();
        }
        else
        {
            this.random = new SecureRandom();
            kParam = (AsymmetricKeyParameter)param;
        }

        
        if (!(kParam instanceof DHPrivateKeyParameters))
        {
            throw new IllegalArgumentException("DHEngine expects DHPrivateKeyParameters");
        }

        this.key = (DHPrivateKeyParameters)kParam;
        this.dhParams = key.getParameters();
    }

    /**
     * calculate our initial message.
     */
    public BigInteger calculateMessage()
    {
        DHKeyPairGenerator dhGen = new DHKeyPairGenerator();
        dhGen.init(new DHKeyGenerationParameters(random, dhParams));
        AsymmetricCipherKeyPair dhPair = dhGen.generateKeyPair();

        this.privateValue = ((DHPrivateKeyParameters)dhPair.getPrivate()).getX();

        return ((DHPublicKeyParameters)dhPair.getPublic()).getY();
    }

    /**
     * given a message from a given party and the corresponding public key,
     * calculate the next message in the agreement sequence. In this case
     * this will represent the shared secret.
     */
    public BigInteger calculateAgreement(DHPublicKeyParameters pub, BigInteger message)
    {
        if (pub == null)
        {
            throw new NullPointerException("'pub' cannot be null");
        }
        if (message == null)
        {
            throw new NullPointerException("'message' cannot be null");
        }

        if (!pub.getParameters().equals(dhParams))
        {
            throw new IllegalArgumentException("Diffie-Hellman public key has wrong parameters.");
        }

        BigInteger p = dhParams.getP();

        // Both peer-supplied values are raised to our (potentially static) private key, so both must
        // satisfy the DH public-value range/subgroup checks; otherwise a peer can submit a small-order
        // or out-of-range element to mount a small-subgroup confinement attack and, when our private
        // key is reused, recover it via CRT.
        BigInteger peerMessage = validatePeerValue(message);
        BigInteger peerY = validatePeerValue(pub.getY());

        BigInteger result = peerY.modPow(privateValue, p);
        if (result.compareTo(ONE) == 0)
        {
            throw new IllegalStateException("Shared key can't be 1");
        }

        return peerMessage.modPow(key.getX(), p).multiply(result).mod(p);
    }

    // 1.46's DHPublicKeyParameters does not validate Y, so the checks of later releases' constructor are made here
    private BigInteger validatePeerValue(BigInteger y)
    {
        BigInteger p = dhParams.getP();

        if (y.compareTo(TWO) < 0 || y.compareTo(p.subtract(TWO)) > 0)
        {
            throw new IllegalArgumentException("invalid DH public key");
        }

        BigInteger q = dhParams.getQ();
        if (q != null && !ONE.equals(y.modPow(q, p)))
        {
            throw new IllegalArgumentException("Y value does not appear to be in correct group");
        }

        return y;
    }
}
