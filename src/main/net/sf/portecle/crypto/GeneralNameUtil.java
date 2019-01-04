package sf.portecle.crypto;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;

public class GeneralNameUtil {

    public static final String IP_PREFIX = "IP:";

    private GeneralNameUtil(){

    }

    public static void generateGeneralName(final String sDnsName, final JcaX509v3CertificateBuilder certBuilder) throws CertIOException {
        if (sDnsName != null)
        {
            GeneralNames generalnames =
                new GeneralNames(new GeneralName[] { getGeneralName(sDnsName) });
            certBuilder.addExtension(Extension.subjectAlternativeName, false, generalnames);
        }
    }

    private static GeneralName getGeneralName(final String sDnsName) {
        if(sDnsName.startsWith(IP_PREFIX)) {
            return new GeneralName(GeneralName.iPAddress, sDnsName.substring(IP_PREFIX.length()));
        }
        return new GeneralName(GeneralName.dNSName, sDnsName);
    }
}
