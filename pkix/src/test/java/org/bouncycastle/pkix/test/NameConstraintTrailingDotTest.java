package org.bouncycastle.pkix.test;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.pkix.PKIXNameConstraintValidator;
import org.bouncycastle.pkix.PKIXNameConstraintValidatorException;

public class NameConstraintTrailingDotTest
    extends TestCase
{
    public void testTrailingDotIsExcluded()
        throws Exception
    {
        String[][] cases = {
            { "1", "bank.com", "ceo@bank.com." },
            { "1", ".bank.com", "ceo@www.bank.com." },
            { "6", "competitor.example", "https://competitor.example./" },
            { "6", ".competitor.example", "https://www.competitor.example./" },
            { "2", "bank.com", "bank.com." },
            { "2", "bank.com", "www.bank.com." }
        };

        for (int i = 0; i != cases.length; i++)
        {
            int tag = Integer.parseInt(cases[i][0]);
            PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();
            validator.addExcludedSubtree(new GeneralSubtree(new GeneralName(tag, cases[i][1])));
            try
            {
                validator.checkExcluded(new GeneralName(tag, cases[i][2]));
                fail(cases[i][2] + " must be caught by the excluded " + cases[i][1] + " subtree");
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }
    }

    public void testNameWithoutTrailingDotStillPermitted()
        throws Exception
    {
        PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();
        validator.intersectPermittedSubtree(new GeneralSubtree(new GeneralName(GeneralName.rfc822Name, "bank.com")));
        validator.checkPermitted(new GeneralName(GeneralName.rfc822Name, "ceo@bank.com"));
        validator.checkPermitted(new GeneralName(GeneralName.rfc822Name, "ceo@bank.com."));
    }
}
