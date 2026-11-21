package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.NoSuchProviderException;
import java.security.Provider;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.jcajce.JceAlgorithmIdentifierConverter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public abstract class RecipientInformation
{
    protected RecipientId rid;
    protected AlgorithmIdentifier   keyEncAlg;
    protected AlgorithmIdentifier messageAlgorithm;
    protected CMSSecureReadable     secureReadable;

    private AuthAttributesProvider additionalData;

    private byte[] resultMac;
    private byte[] contentDigest;
    private RecipientOperator     operator;

    RecipientInformation(
        AlgorithmIdentifier     keyEncAlg,
        AlgorithmIdentifier     messageAlgorithm,
        CMSSecureReadable       secureReadable,
        AuthAttributesProvider  additionalData)
    {
        this.keyEncAlg = keyEncAlg;
        this.messageAlgorithm = messageAlgorithm;
        this.secureReadable = secureReadable;
        this.additionalData = additionalData;
    }

    public RecipientId getRID()
    {
        return rid;
    }

    private byte[] encodeObj(
        ASN1Encodable obj)
        throws IOException
    {
        if (obj != null)
        {
            return obj.toASN1Primitive().getEncoded();
        }

        return null;
    }

    /**
     * Return the key encryption algorithm details for the key in this recipient.
     *
     * @return AlgorithmIdentifier representing the key encryption algorithm.
     */
    public AlgorithmIdentifier getKeyEncryptionAlgorithm()
    {
        return keyEncAlg;
    }

    /**
     * return the object identifier for the key encryption algorithm.
     *
     * @return OID for key encryption algorithm.
     */
    public String getKeyEncryptionAlgOID()
    {
        return keyEncAlg.getObjectId().getId();
    }

    /**
     * return the ASN.1 encoded key encryption algorithm parameters, or null if
     * there aren't any.
     *
     * @return ASN.1 encoding of key encryption algorithm parameters.
     */
    public byte[] getKeyEncryptionAlgParams()
    {
        try
        {
            return encodeObj(keyEncAlg.getParameters());
        }
        catch (Exception e)
        {
            throw new RuntimeException("exception getting encryption parameters " + e);
        }
    }

    /**
     * Return an AlgorithmParameters object giving the encryption parameters
     * used to encrypt the key this recipient holds.
     *
     * @param provider the provider to generate the parameters for.
     * @return the parameters object, null if there is not one.
     * @throws CMSException            if the algorithm cannot be found, or the parameters can't be parsed.
     * @throws NoSuchProviderException if the provider cannot be found.
     * @deprecated use getKeyEncryptionAlgorithm and JceAlgorithmIdentifierConverter().
     */
    public AlgorithmParameters getKeyEncryptionAlgorithmParameters(
        String provider)
        throws CMSException, NoSuchProviderException
    {
        return new JceAlgorithmIdentifierConverter().setProvider(provider).getAlgorithmParameters(keyEncAlg);
    }

    /**
     * Return an AlgorithmParameters object giving the encryption parameters
     * used to encrypt the key this recipient holds.
     *
     * @param provider the provider to generate the parameters for.
     * @return the parameters object, null if there is not one.
     * @throws CMSException if the algorithm cannot be found, or the parameters can't be parsed.
     * @deprecated use getKeyEncryptionAlgorithm and JceAlgorithmIdentifierConverter().
     */
    public AlgorithmParameters getKeyEncryptionAlgorithmParameters(
        Provider provider)
        throws CMSException
    {
        return new JceAlgorithmIdentifierConverter().setProvider(provider).getAlgorithmParameters(keyEncAlg);
    }

    /**
     * @deprecated use getContent(Recipient)
     */
    public byte[] getContent(
        Key key,
        String provider)
        throws CMSException, NoSuchProviderException
    {
        return getContent(key, CMSUtils.getProvider(provider));
    }

    /**
     * @deprecated use getContent(Recipient)
     */
    public byte[] getContent(
        Key key,
        Provider provider)
        throws CMSException
    {
        try
        {
            return CMSUtils.streamToByteArray(getContentStream(key, provider).getContentStream());
        }
        catch (IOException e)
        {
            throw new RuntimeException("unable to parse internal stream: " + e);
        }
    }

    /**
     * Return the content digest calculated during the read of the content if one has been generated. This will
     * only happen if we are dealing with authenticated data and authenticated attributes are present.
     *
     * @return byte array containing the digest.
     */
    public byte[] getContentDigest()
    {
        // Cache the computed digest: the underlying DigestCalculator.getDigest() finalises (resets)
        // the digest, so it must be read exactly once. getMac() now also needs this value (to bind
        // the content to the MAC), so without caching a getMac() call would consume the digest and a
        // later getContentDigest() would return the digest of an empty input.
        if (contentDigest == null
            && secureReadable instanceof CMSEnvelopedHelper.CMSDigestAuthenticatedSecureReadable)
        {
            contentDigest = ((CMSEnvelopedHelper.CMSDigestAuthenticatedSecureReadable)secureReadable).getDigest();
        }

        return contentDigest;
    }

    /**
     * Return the MAC calculated for the recipient. Note: this call is only meaningful once all
     * the content has been read.
     *
     * @return  byte array containing the mac.
     */
    public byte[] getMac()
    {
        if (resultMac == null)
        {
            if (operator.isMacBased())
            {
                if (additionalData != null)
                {
                    // RFC 5652 sec. 9.3: with authenticated attributes present the MAC is computed over the
                    // attributes, not the content, so the content is bound to the MAC only through the
                    // messageDigest authenticated attribute. Verify that the digest computed over the
                    // content just read matches that attribute before producing the MAC; otherwise an
                    // attacker could replace encapContentInfo.eContent while leaving authAttrs and the MAC
                    // untouched and a recipient comparing only getMac() values would accept the forgery.
                    checkContentDigestMatchesMessageDigestAttribute();

                    try
                    {
                        Streams.drain(operator.getInputStream(new ByteArrayInputStream(additionalData.getAuthAttributes().getEncoded(ASN1Encoding.DER))));
                    }
                    catch (IOException e)
                    {
                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                    }
                }
                resultMac = operator.getMac();
            }
        }

        return resultMac;
    }

    private void checkContentDigestMatchesMessageDigestAttribute()
    {
        byte[] contentDigest = getContentDigest();
        if (contentDigest == null)
        {
            throw new CMSRuntimeException("unable to verify messageDigest attribute: content digest not available");
        }

        Attribute messageDigestAttr = new AttributeTable(additionalData.getAuthAttributes()).get(CMSAttributes.messageDigest);
        if (messageDigestAttr == null || messageDigestAttr.getAttrValues().size() != 1)
        {
            throw new CMSRuntimeException("AuthenticatedData missing or malformed messageDigest authenticated attribute");
        }

        byte[] expectedDigest = ASN1OctetString.getInstance(messageDigestAttr.getAttrValues().getObjectAt(0)).getOctets();
        if (!Arrays.constantTimeAreEqual(contentDigest, expectedDigest))
        {
            throw new CMSRuntimeException("content digest does not match messageDigest authenticated attribute");
        }
    }

    /**
     * Return the decrypted/encapsulated content in the EnvelopedData after recovering the content
     * encryption/MAC key using the passed in Recipient.
     *
     * @param recipient recipient object to use to recover content encryption key
     * @return  the content inside the EnvelopedData this RecipientInformation is associated with.
     * @throws CMSException if the content-encryption/MAC key cannot be recovered.
     */
    public byte[] getContent(
        Recipient recipient)
        throws CMSException
    {
        try
        {
            return CMSUtils.streamToByteArray(getContentStream(recipient).getContentStream());
        }
        catch (IOException e)
        {
            throw new CMSException("unable to parse internal stream: " + e.getMessage(), e);
        }
    }

    /**
     * decrypt the content and return it
     * @deprecated use getContentStream(Recipient) method
     */
    public CMSTypedStream getContentStream(Key key, String provider)
        throws CMSException, NoSuchProviderException
    {
        return getContentStream(key, CMSUtils.getProvider(provider));
    }

    /**
     * decrypt the content and return it
     * @deprecated use getContentStream(Recipient) method
     */
    public abstract CMSTypedStream getContentStream(Key key, Provider provider)
        throws CMSException;


    /**
     * Return a CMSTypedStream representing the content in the EnvelopedData after recovering the content
     * encryption/MAC key using the passed in Recipient.
     *
     * @param recipient recipient object to use to recover content encryption key
     * @return  the content inside the EnvelopedData this RecipientInformation is associated with.
     * @throws CMSException if the content-encryption/MAC key cannot be recovered.
     */
    public CMSTypedStream getContentStream(Recipient recipient)
        throws CMSException, IOException
    {
        operator = getRecipientOperator(recipient);

        if (additionalData != null)
        {
            return new CMSTypedStream(secureReadable.getInputStream());
        }

        return new CMSTypedStream(operator.getInputStream(secureReadable.getInputStream()));
    }

    protected abstract RecipientOperator getRecipientOperator(Recipient recipient)
        throws CMSException, IOException;
}
