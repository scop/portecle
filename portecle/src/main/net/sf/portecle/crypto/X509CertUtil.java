/*
 * X509CertUtil.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004 Ville Skyttä, ville.skytta@iki.fi
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

package net.sf.portecle.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Vector;

import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.X509V1CertificateGenerator;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.Base64;

/**
 * Provides utility methods relating to X509 Certificates, CRLs and CSRs.
 */
public final class X509CertUtil
{
    /** PKCS #7 encoding name */
    public static final String PKCS7_ENCODING = "PKCS7";

    /** PkiPath encoding name */
    public static final String PKIPATH_ENCODING = "PkiPath";

    /** OpenSSL PEM encoding name */
    public static final String OPENSSL_PEM_ENCODING = "OpenSSL_PEM";

    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/crypto/resources");

    /** Type name for X.509 certificates */
    private static final String X509_CERT_TYPE = "X.509";

    /** Begin certificate for PEM encoding */
    private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";

    /** End certificate for PEM encoding */
    private static final String END_CERT = "-----END CERTIFICATE-----";

    /** The maximum length of lines in printable encoded certificates */
    private static final int CERT_LINE_LENGTH = 64;

    /** Begin certification request for PEM encoding */
    private static final String BEGIN_CERT_REQ =
        "-----BEGIN CERTIFICATE REQUEST-----";

    /** End certification request for PEM encoding */
    private static final String END_CERT_REQ =
        "-----END CERTIFICATE REQUEST-----";

    /** The maximum length of lines in certification requests */
    private static final int CERT_REQ_LINE_LENGTH = 76;

    /**
     * Private to prevent construction.
     */
    private X509CertUtil() {}

    /**
     * Load one or more certificates from the specified file.
     *
     * @param fCertFile The file to load certificates from
     * @param encoding The certification path encoding.  If null, treat as a
     * normal certificate, not certification path.  Use one of the
     * <code>*_ENCODING</code> constants here.
     * @return The certificates
     * @throws CryptoException Problem encountered while loading the
     * certificate(s)
     * @throws FileNotFoundException If the certificate file does not
     * exist, is a directory rather than a regular file, or for some
     * other reason cannot be opened for reading
     * @throws IOException An I/O error occurred
     */
    public static X509Certificate[] loadCertificates(File fCertFile,
                                                     String encoding)
        throws CryptoException, IOException
    {
        ArrayList vCerts = new ArrayList();

        FileInputStream fis = null;

        try
        {
            fis = new FileInputStream(fCertFile);

            CertificateFactory cf =
                CertificateFactory.getInstance(X509_CERT_TYPE);

            Collection coll = null;

            if (OPENSSL_PEM_ENCODING.equals(encoding)) {
                // Special case; this is not a real JCE supported encoding.
                PEMReader pr = new PEMReader(new InputStreamReader(fis),
                                             null, cf.getProvider().getName());
                /* These beasts can contain just about anything, and
                   unfortunately the PEMReader API (as of BC 1.25) won't allow
                   us to really skip things we're not interested in; stuff
                   happens already in readObject().  This may cause some weird
                   exception messages for non-certificate objects in the
                   "stream" for example passphrase related ones for protected
                   private keys.  Well, I guess this is better than nothing
                   though... :( */
                Object cert;
                while ((cert = pr.readObject()) != null) {
                    if (cert instanceof X509Certificate) {
                        // "Short-circuit" into vCerts, not using coll.
                        vCerts.add(cert);
                    }
                    // Skip other stuff, at least for now.
                }
            }
            else if (encoding != null) {
                // Try it as a certification path of the specified type
                coll = cf.generateCertPath(fis, encoding).getCertificates();
            }
            else {
                // "Normal" certificate(s)
                coll = cf.generateCertificates(fis);
            }

            if (coll != null) {
                for (Iterator iter = coll.iterator(); iter.hasNext(); ) {
                    X509Certificate cert = (X509Certificate)iter.next();
                    if (cert != null) {
                        vCerts.add(cert);
                    }
                }
            }
        }
        // Some RuntimeExceptions which really ought to be
        // CertificateExceptions may be thrown from cf.generateCert* above,
        // for example Sun's PKCS #7 parser tends to throw them... :P
        catch (Exception ex) {
            // TODO: don't throw if vCerts non-empty (eg. OpenSSL PEM above)?
            throw new CryptoException(
                m_res.getString("NoLoadCertificate.exception.message"), ex);
        }
        finally {
            if (fis != null) {
                try {fis.close();} catch(IOException ex) { /* Ignore */ }}
        }

        return (X509Certificate[])
            vCerts.toArray(new X509Certificate[vCerts.size()]);
    }

    /**
     * Load a CRL from the specified file.
     *
     * @param fCRLFile The file to load CRL from
     * @return The CRL
     * @throws CryptoException Problem encountered while loading the CRL
     * @throws FileNotFoundException If the CRL file does not exist,
     *                               is a directory rather than a regular
     *                               file, or for some other reason cannot
     *                               be opened for reading
     * @throws IOException An I/O error occurred
     */
    public static X509CRL loadCRL(File fCRLFile)
        throws CryptoException, IOException
    {
        FileInputStream fis = null;

        try
        {
            fis = new FileInputStream(fCRLFile);
            CertificateFactory cf =
                CertificateFactory.getInstance(X509_CERT_TYPE);
            X509CRL crl = (X509CRL)cf.generateCRL(fis);
            return crl;
        }
        catch (GeneralSecurityException ex)
        {
            throw new CryptoException(
                m_res.getString("NoLoadCrl.exception.message"), ex);
        }
        finally
        {
            if (fis != null) {
                try {fis.close();} catch(IOException ex) { /* Ignore */ }}
        }
    }

    /**
     * Load a CSR from the specified file.
     *
     * @param fCSRFile The file to load CSR from
     * @return The CSR
     * @throws CryptoException Problem encountered while loading the CSR
     * @throws FileNotFoundException If the CSR file does not exist,
     *                               is a directory rather than a regular
     *                               file, or for some other reason cannot
     *                               be opened for reading
     * @throws IOException An I/O error occurred
     */
    public static PKCS10CertificationRequest loadCSR(File fCSRFile)
        throws CryptoException, IOException
    {
        InputStreamReader isr = null;
        StringWriter sw = null;
        LineNumberReader lnr = null;

        try
        {
            // Read content of file into a string
            isr = new InputStreamReader(new FileInputStream(fCSRFile));
            sw = new StringWriter();

            int iRead;
            char[] buff = new char[1024];

            while ((iRead = isr.read(buff, 0, buff.length)) != -1)
            {
                sw.write(buff, 0, iRead);
            }

            // Strip out extraneous content such as headers, footers, empty
            // lines and line breaks
            StringBuffer strBuff = new StringBuffer();

            lnr = new LineNumberReader(new StringReader(sw.toString()));

            String sLine = null;
            while ((sLine = lnr.readLine()) != null) // Gets rid of line breaks
            {
                if (sLine.length() > 0) // Not interested in empty lines
                {
                    char c = sLine.charAt(0);

                    // Not interested in lines that do not start with a
                    // Base 64 character
                    if (((c > 'A') && (c <= 'Z')) ||
                        ((c > 'a') && (c <= 'z')) ||
                        ((c > '0') && (c <= '9')) ||
                        (c == '+') || (c == '/') || (c == '='))
                    {
                        strBuff.append(sLine);
                    }
                }
            }

            // Decode Base 64 string to byte array
            byte[] bDecodedReq = Base64.decode(strBuff.toString());

            // Create CSR from decoded byte array
            PKCS10CertificationRequest csr =
                new PKCS10CertificationRequest(bDecodedReq);

            // Verify CSR
            if (!csr.verify())
            {
                throw new CryptoException(
                    m_res.getString("NoVerifyCsr.exception.message"));
            }

            // Return CSR
            return csr;
        }
        catch (GeneralSecurityException ex)
        {
            throw new CryptoException(
                m_res.getString("NoLoadCsr.exception.message"), ex);
        }

        finally
        {
            if (isr != null) {
                try { isr.close(); } catch(IOException ex) { /* Ignore */ }}
            if (sw != null) {
                try { sw.close();  } catch(IOException ex) { /* Ignore */ }}
            if (lnr != null) {
                try { lnr.close(); } catch(IOException ex) { /* Ignore */ }}
        }
    }

    /**
     * Convert the supplied array of certificate objects into
     * X509Certificate objects.
     *
     * @param certsIn The Certificate objects
     * @return The converted X509Certificate objects
     * @throws CryptoException A problem occurred during the conversion
     */
    public static X509Certificate[] convertCertificates(Certificate[] certsIn)
        throws CryptoException
    {
        X509Certificate[] certsOut = new X509Certificate[certsIn.length];

        for (int iCnt=0; iCnt < certsIn.length; iCnt++)
        {
            certsOut[iCnt] = convertCertificate(certsIn[iCnt]);
        }

        return certsOut;
    }

    /**
     * Convert the supplied certificate object into an X509Certificate object.
     *
     * @param certIn The Certificate object
     * @return The converted X509Certificate object
     * @throws CryptoException A problem occurred during the conversion
     */
    public static X509Certificate convertCertificate(Certificate certIn)
        throws CryptoException
    {
        try
        {
            CertificateFactory cf =
                CertificateFactory.getInstance(X509_CERT_TYPE);
            ByteArrayInputStream bais =
                new ByteArrayInputStream(certIn.getEncoded());
            return (X509Certificate)cf.generateCertificate(bais);
        }
        catch (CertificateException ex)
        {
            throw new CryptoException(
                m_res.getString("NoConvertCertificate.exception.message"), ex);
        }
    }

    /**
     * Attempt to order the supplied array of X.509 certificates in issued to
     * to issued from order.
     *
     * @param certs The X.509 certificates in order
     * @return The ordered X.509 certificates
     */
    public static X509Certificate[] orderX509CertChain(X509Certificate[] certs)
    {
        int iOrdered = 0;
        X509Certificate[] tmpCerts = (X509Certificate[])certs.clone();
        X509Certificate[] orderedCerts = new X509Certificate[certs.length];

        X509Certificate issuerCert = null;

        // Find the root issuer (ie certificate where issuer is the same
        // as subject)
        for (int iCnt=0; iCnt < tmpCerts.length; iCnt++)
        {
            X509Certificate aCert = tmpCerts[iCnt];
            if (aCert.getIssuerDN().equals(aCert.getSubjectDN()))
            {
                issuerCert = aCert;
                orderedCerts[iOrdered] = issuerCert;
                iOrdered++;
            }
        }

        // Couldn't find a root issuer so just return the un-ordered array
        if (issuerCert == null)
        {
            return certs;
        }

        // Keep making passes through the array of certificates looking for the
        // next certificate in the chain until the links run out
        while (true)
        {
            boolean bFoundNext = false;
            for (int iCnt=0; iCnt < tmpCerts.length; iCnt++)
            {
                X509Certificate aCert = tmpCerts[iCnt];

                // Is this certificate the next in the chain?
                if (aCert.getIssuerDN().equals(issuerCert.getSubjectDN()) &&
                    aCert != issuerCert)
                {
                    // Yes
                    issuerCert = aCert;
                    orderedCerts[iOrdered] = issuerCert;
                    iOrdered++;
                    bFoundNext = true;
                    break;
                }
            }
            if (!bFoundNext)
            {
                break;
            }
        }

        // Resize array
        tmpCerts = new X509Certificate[iOrdered];
        System.arraycopy(orderedCerts, 0, tmpCerts, 0, iOrdered);

        // Reverse the order of the array
        orderedCerts = new X509Certificate[iOrdered];

        for (int iCnt=0; iCnt < iOrdered; iCnt++)
        {
            orderedCerts[iCnt] = tmpCerts[tmpCerts.length - 1 - iCnt];
        }

        return orderedCerts;
    }

    /**
     * DER encode a certificate.
     *
     * @return The binary encoding
     * @param cert The certificate
     * @throws CryptoException If there was a problem encoding the certificate
     */
    public static byte[] getCertEncodedDer(X509Certificate cert)
        throws CryptoException
    {
        try
        {
            return cert.getEncoded();
        }
        catch (CertificateException ex)
        {
            throw new CryptoException(
                m_res.getString("NoDerEncode.exception.message"), ex);
        }
    }

    /**
     * PEM encode a certificate.
     *
     * @return The printable encoding
     * @param cert The certificate
     * @throws CryptoException If there was a problem encoding the certificate
     */
    public static String getCertEncodedPem(X509Certificate cert)
        throws CryptoException
    {
        try
        {
            // Get Base 64 encoding of certificate
            String sTmp = new String(Base64.encode(cert.getEncoded()));

            // Certificate encodng is bounded by a header and footer
            String sEncoded = BEGIN_CERT + "\n";

            // Limit line lengths between header and footer
            for (int iCnt=0; iCnt < sTmp.length(); iCnt += CERT_LINE_LENGTH)
            {
                int iLineLength;

                if ((iCnt + CERT_LINE_LENGTH) > sTmp.length())
                {
                    iLineLength = sTmp.length() - iCnt;
                }
                else
                {
                    iLineLength = CERT_LINE_LENGTH;
                }

                sEncoded += sTmp.substring(iCnt, iCnt + iLineLength) + "\n";
            }

            // Footer
            sEncoded += END_CERT + "\n";

            return sEncoded;
        }
        catch (CertificateException ex)
        {
            throw new CryptoException(
                m_res.getString("NoPemEncode.exception.message"), ex);
        }
    }

    /**
     * PKCS #7 encode a certificate.
     *
     * @return The PKCS #7 encoded certificate
     * @param cert The certificate
     * @throws CryptoException If there was a problem encoding the certificate
     */
    public static byte[] getCertEncodedPkcs7(X509Certificate cert)
        throws CryptoException
    {
        return getCertsEncodedPkcs7(new X509Certificate[] {cert});
    }

    /**
     * PKCS #7 encode a number of certificates.
     *
     * @return The PKCS #7 encoded certificates
     * @param certs The certificates
     * @throws CryptoException If there was a problem encoding the certificates
     */
    public static byte[] getCertsEncodedPkcs7(X509Certificate[] certs)
        throws CryptoException
    {
        return getCertsEncoded(
            certs, PKCS7_ENCODING, "NoPkcs7Encode.exception.message");
    }

    /**
     * PkiPath encode a certificate.
     *
     * @return The PkiPath encoded certificate
     * @param cert The certificate
     * @throws CryptoException If there was a problem encoding the certificate
     */
    public static byte[] getCertEncodedPkiPath(X509Certificate cert)
        throws CryptoException
    {
        return getCertsEncodedPkiPath(new X509Certificate[] {cert});
    }

    /**
     * PkiPath encode a number of certificates.
     *
     * @return The PkiPath encoded certificates
     * @param certs The certificates
     * @throws CryptoException If there was a problem encoding the certificates
     */
    public static byte[] getCertsEncodedPkiPath(X509Certificate[] certs)
        throws CryptoException
    {
        return getCertsEncoded(
            certs, PKIPATH_ENCODING, "NoPkiPathEncode.exception.message");
    }

    /**
     * Encode a number of certificates using the given encoding.
     *
     * @return The encoded certificates
     * @param certs The certificates
     * @param encoding The encoding
     * @param errkey The error message key to use in the possibly occurred
     * exception
     * @throws CryptoException If there was a problem encoding the certificates
     */
    private static byte[] getCertsEncoded(X509Certificate[] certs,
                                          String encoding, String errkey)
        throws CryptoException
    {
        try
        {
            CertificateFactory cf =
                CertificateFactory.getInstance(X509_CERT_TYPE);
            return cf.generateCertPath(
                Arrays.asList(certs)).getEncoded(encoding);
        }
        catch (CertificateException ex)
        {
            throw new CryptoException(m_res.getString(errkey), ex);
        }
    }

    /**
     * Generate a self-signed X509 Version 1 certificate for the supplied key
     * pair and signature algorithm.
     *
     * @return The generated certificate
     * @param sCommonName Common name certficate attribute
     * @param sOrganisationUnit Organisation Unit certificate attribute
     * @param sOrganisation Organisation certificate attribute
     * @param sLocality Locality certificate
     * @param sState State certificate attribute
     * @param sEmailAddress Email Address certificate attribute
     * @param sCountryCode Country Code certificate attribute
     * @param iValidity Validity period of cerficate in days
     * @param publicKey Public part of key pair
     * @param privateKey Private part of key pair
     * @param signatureType Signature Type
     * @throws CryptoException If there was a problem generating the
     * certificate
     */
    public static X509Certificate generateCert(String sCommonName,
                                               String sOrganisationUnit,
                                               String sOrganisation,
                                               String sLocality,
                                               String sState,
                                               String sCountryCode,
                                               String sEmailAddress,
                                               int iValidity,
                                               PublicKey publicKey,
                                               PrivateKey privateKey,
                                               SignatureType signatureType)
        throws CryptoException
    {
        // Holds certificate attributes
        Hashtable attrs = new Hashtable();
        Vector vOrder = new Vector();

        // Load certificate attributes
        if (sCommonName != null)
        {
            attrs.put(X509Principal.CN, sCommonName);
            vOrder.add(0, X509Principal.CN);
        }

        if (sOrganisationUnit != null)
        {
            attrs.put(X509Principal.OU, sOrganisationUnit);
            vOrder.add(0, X509Principal.OU);
        }

        if (sOrganisation != null)
        {
            attrs.put(X509Principal.O, sOrganisation);
            vOrder.add(0, X509Principal.O);
        }

        if (sLocality != null)
        {
            attrs.put(X509Principal.L, sLocality);
            vOrder.add(0, X509Principal.L);
        }

        if (sState != null)
        {
            attrs.put(X509Principal.ST, sState);
            vOrder.add(0, X509Principal.ST);
        }

        if (sCountryCode != null)
        {
            attrs.put(X509Principal.C, sCountryCode);
            vOrder.add(0, X509Principal.C);
        }

        if (sEmailAddress != null)
        {
            attrs.put(X509Principal.E, sEmailAddress);
            vOrder.add(0, X509Principal.E);
        }

        // Get an X509 Version 1 Certificate generator
        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();

        // Load the generator with generation parameters

        // Set the issuer distinguished name
        certGen.setIssuerDN(new X509Principal(vOrder, attrs));

        // Valid before and after dates now to iValidity days in the future
        certGen.setNotBefore(new Date(System.currentTimeMillis()));
        certGen.setNotAfter(new Date(System.currentTimeMillis() +
                                     ((long)iValidity * 24 * 60 * 60 * 1000)));

        // Set the subject distinguished name (same as issuer for our purposes)
        certGen.setSubjectDN(new X509Principal(vOrder, attrs));

        // Set the public key
        certGen.setPublicKey(publicKey);

        // Set the algorithm
        certGen.setSignatureAlgorithm(signatureType.toString());

        // Set the serial number
        certGen.setSerialNumber(generateX509SerialNumber());

        try
        {
            // Generate an X.509 certificate, based on the current issuer and
            // subject
            X509Certificate cert = certGen.generateX509Certificate(privateKey);

            // Return the certificate
            return cert;
        }
        // Something went wrong
        catch (GeneralSecurityException ex)
        {
            throw new CryptoException(
                m_res.getString("CertificateGenFailed.exception.message"), ex);
        }
    }

    /**
     * Generate a unique serial number for use as an X509 serial number.
     *
     * @return The unique serial number
     */
    private static BigInteger generateX509SerialNumber()
    {
        // Time in seconds
        return new BigInteger(
            Long.toString(System.currentTimeMillis() / 1000));
    }

    /**
     * Create a PKCS #10 certification request (CSR) using the supplied
     * certificate and private key.
     *
     * @param cert The certificate
     * @param privateKey The private key
     * @throws CryptoException If there was a problem generating the CSR
     * @return The CSR
     */
    public static String generatePKCS10CSR(X509Certificate cert,
                                           PrivateKey privateKey)
        throws CryptoException
    {
        X509Name subject = new X509Name(cert.getSubjectDN().toString());

        try
        {
            PKCS10CertificationRequest csr =
                new PKCS10CertificationRequest(cert.getSigAlgName(),
                                               subject,
                                               cert.getPublicKey(),
                                               null,
                                               privateKey);
            if (!csr.verify())
            {
                throw new CryptoException(
                    m_res.getString("NoVerifyGenCsr.exception.message"));
            }

            // Get Base 64 encoding of CSR
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DEROutputStream deros = new DEROutputStream(baos);
            deros.writeObject(csr.getDERObject());
            String sTmp = new String(Base64.encode(baos.toByteArray()));

            // CSR is bounded by a header and footer
            String sCsr = BEGIN_CERT_REQ + "\n";

            // Limit line lengths between header and footer
            for (int iCnt=0; iCnt < sTmp.length(); iCnt +=CERT_REQ_LINE_LENGTH)
            {
                int iLineLength;

                if ((iCnt + CERT_REQ_LINE_LENGTH) > sTmp.length())
                {
                    iLineLength = sTmp.length() - iCnt;
                }
                else
                {
                    iLineLength = CERT_REQ_LINE_LENGTH;
                }

                sCsr += sTmp.substring(iCnt, iCnt + iLineLength) + "\n";
            }

            // Footer
            sCsr += END_CERT_REQ + "\n";

            return sCsr;
        }
        catch (GeneralSecurityException ex)
        {
            throw new CryptoException(
                m_res.getString("NoGenerateCsr.exception.message"), ex);
        }
        catch (IOException ex)
        {
            throw new CryptoException(
                m_res.getString("NoGenerateCsr.exception.message"), ex);
        }
    }

    /**
     * Verify that one X.509 certificate was signed using the private key that
     * corresponds to the public key of a second certificate.
     *
     * @return True if the first certificate was signed by private key
     *         corresponding to the second signature
     * @param signedCert The signed certificate
     * @param signingCert The signing certificate
     * @throws CryptoException If there was a problem verifying the signature.
     */
    public static boolean verifyCertificate(X509Certificate signedCert,
                                            X509Certificate signingCert)
        throws CryptoException
    {
        try
        {
            signedCert.verify(signingCert.getPublicKey());
        }
        // Verification failed
        catch (InvalidKeyException ex)
        {
            return false;
        }
        // Verification failed
        catch (SignatureException ex)
        {
            return false;
        }
        // Problem verifying
        catch (GeneralSecurityException ex)
        {
            throw new CryptoException(
                m_res.getString("NoVerifyCertificate.exception.message"), ex);
        }
        return true;
    }

    /**
     * Check whether or not a trust path exists between the supplied
     * X.509 certificate and and the supplied keystores based on the
     * trusted certificates contained therein, ie that a chain of
     * trust exists between the supplied certificate and a self-signed
     * trusted certificate in the KeyStores.
     *
     * @return The trust chain, or null if trust could not be established
     * @param cert The certificate
     * @param keyStores The KeyStores
     * @throws CryptoException If there is a problem establishing trust
     */
    public static X509Certificate[] establishTrust(KeyStore[] keyStores,
                                                   X509Certificate cert)
        throws CryptoException
    {
        // Extract all certificates from the Keystores creating
        ArrayList ksCerts = new ArrayList();
        for (int iCnt=0; iCnt < keyStores.length; iCnt++)
        {
            ksCerts.addAll(extractCertificates(keyStores[iCnt]));
        }

        // Try and establish trust against the set of all certificates
        return establishTrust(ksCerts, cert);
    }

    /**
     * Check whether or not a trust path exists between the supplied
     * X.509 certificate and and the supplied comparison certificates
     * based on the trusted certificates contained therein, ie that a
     * chain of trust exists between the supplied certificate and a
     * self-signed trusted certificate in the comparison set.
     *
     * @return The trust chain, or null if trust could not be established
     * @param cert The certificate
     * @param vCompCerts The comparison set of certificates
     * @throws CryptoException If there is a problem establishing trust
     */
    private static X509Certificate[] establishTrust(List vCompCerts,
                                                    X509Certificate cert)
        throws CryptoException
    {
        // For each comparison certificate...
        for (int iCnt=0; iCnt < vCompCerts.size(); iCnt++)
        {
            X509Certificate compCert = (X509Certificate)vCompCerts.get(iCnt);

            // Check if the Comparison certificate's subject is the same as the
            // certificate's issuer
            if (cert.getIssuerDN().equals(compCert.getSubjectDN()))
            {
                // If so verify with the comparison certificate's corresponding
                // private key was used to sign the certificate
                if (X509CertUtil.verifyCertificate(cert, compCert))
                {
                    // If the KeyStore certificate is self-signed then a
                    // chain of trust exists
                    if (compCert.getSubjectDN().equals(compCert.getIssuerDN()))
                    {
                        return new X509Certificate[]{cert, compCert};
                    }
                    // Otherwise try and establish a chain of trust for
                    // the comparison certificate against the other comparison
                    // certificates
                    X509Certificate[] tmpChain =
                        establishTrust(vCompCerts, compCert);
                    if (tmpChain != null) {
                        X509Certificate[] trustChain =
                            new X509Certificate[tmpChain.length + 1];
                        trustChain[0] = cert;
                        for (int j = 1; j <= tmpChain.length; j++) {
                            trustChain[j] = tmpChain[j-1];
                        }
                        return trustChain;
                    }
                }
            }
        }

        // No chain of trust
        return null;
    }

    /**
     * Extract a copy of all trusted certificates contained within the
     * supplied KeyStore.
     *
     * @param keyStore The KeyStore
     * @return The extracted certificates
     * @throws CryptoException If a problem is encountered extracting
     * the certificates
     */
    private static Collection extractCertificates(KeyStore keyStore)
        throws CryptoException
    {
        try
        {
            ArrayList vCerts = new ArrayList();

            for (Enumeration en = keyStore.aliases(); en.hasMoreElements(); )
            {
                String sAlias = (String) en.nextElement();

                if (keyStore.isCertificateEntry(sAlias))
                {
                    vCerts.add(X509CertUtil.convertCertificate(
                                   keyStore.getCertificate(sAlias)));
                }
            }

            return vCerts;
        }
        catch (KeyStoreException ex)
        {
            throw new CryptoException(
                m_res.getString("NoExtractCertificates.exception.message"),ex);
        }
    }

    /**
     * Check whether or not a trusted certificate in the supplied KeyStore
     * matches the the supplied X.509 certificate.
     *
     * @return The alias of the matching certificate in the KeyStore or null
     *         if there is no match
     * @param cert The certificate
     * @param keyStore The KeyStore
     * @throws CryptoException If there is a problem establishing trust
     */
    public static String matchCertificate(KeyStore keyStore,
                                          X509Certificate cert)
        throws CryptoException
    {
        try
        {
            for (Enumeration en = keyStore.aliases(); en.hasMoreElements(); )
            {
                String sAlias = (String) en.nextElement();
                if (keyStore.isCertificateEntry(sAlias))
                {
                    X509Certificate compCert =
                        X509CertUtil.convertCertificate(
                            keyStore.getCertificate(sAlias));

                    if (cert.equals(compCert))
                    {
                        return sAlias;
                    }
                }
            }
            return null;
        }
        catch (KeyStoreException ex)
        {
            throw new CryptoException(
                m_res.getString("NoMatchCertificate.exception.message"), ex);
        }
    }

    /**
     * For a given X.509 certificate get a representative alias for it
     * in a KeyStore.  For a self-signed certificate this will be the
     * subject's common name (if any).  For a non-self-signed
     * certificate it will be the subject's common name followed by
     * the issuer's common name in brackets.  Alaises will always be
     * in lower case.
     *
     * @param cert The certificate
     * @return The alias or a blank string if none could be worked out
     */
    public static String getCertificateAlias(X509Certificate cert)
    {
        // Get the subject and issuer distinguished names
        Principal subject = cert.getSubjectDN();
        Principal issuer = cert.getIssuerDN();

        // Get the subject's common name
        String sSubject = subject.getName();
        String sSubjectCN = "";
        int iCN = sSubject.indexOf("CN=");
        if (iCN != -1)
        {
            iCN += 3;
            int iEndCN = sSubject.indexOf(", ", iCN);
            if (iEndCN != -1)
            {
                sSubjectCN = sSubject.substring(iCN, iEndCN).toLowerCase();
            }
            else
            {
                sSubjectCN = sSubject.substring(iCN).toLowerCase();
            }
        }

        // Get the issuer's common name
        String sIssuer = issuer.getName();
        String sIssuerCN = "";
        iCN = sIssuer.indexOf("CN=");
        if (iCN != -1)
        {
            iCN += 3;
            int iEndCN = sIssuer.indexOf(", ", iCN);
            if (iEndCN != -1)
            {
                sIssuerCN = sIssuer.substring(iCN, iEndCN).toLowerCase();
            }
            else
            {
                sIssuerCN = sIssuer.substring(iCN).toLowerCase();
            }
        }

        // Could not get a subject CN - return blank
        if (sSubjectCN.length() == 0)
        {
            return "";
        }

        // Self-signed certificate or could not get an issuer CN
        if (subject.equals(issuer) || sIssuerCN.length() == 0) {
            // Alias is the subject CN
            return sSubjectCN;
        }
        // else non-self-signed certificate
        // Alias is the subject CN followed by the issuer CN in brackets
        return MessageFormat.format("{0} ({1})",
                new String[]{sSubjectCN, sIssuerCN});
    }

    
    /**
     * For a given X.509 certificate get the keysize of its public key.
     *
     * @param cert The certificate
     * @return The keysize
     * @throws CryptoException If there is a problem getting the keysize
     */
    public static int getCertificateKeyLength(X509Certificate cert)
        throws CryptoException
    {
        try
        {
            // Get the certificate's public key
            PublicKey pubKey = cert.getPublicKey();

            // Get the public key algorithm
            String sAlgorithm = pubKey.getAlgorithm();
            // TODO: for some certs, eg. some in OpenSSL's certs/ dir in the
            // source tarball, this may return an OID, which will confuse us.

            /* If the algorithm is RSA then use a KeyFactory to create
               an RSA public key spec and get the keysize from the
               modulus length in bits */
            if (sAlgorithm.equals(KeyPairType.RSA.toString()))
            {
                KeyFactory keyFact = KeyFactory.getInstance(sAlgorithm);
                RSAPublicKeySpec keySpec = (RSAPublicKeySpec)
                    keyFact.getKeySpec(pubKey, RSAPublicKeySpec.class);
                BigInteger modulus = keySpec.getModulus();
                return modulus.toString(2).length();
            }
            /* If the algorithm is RSA then use a KeyFactory to create
               a DSA public key spec and get the keysize from the
               prime length in bits */
            else if (sAlgorithm.equals(KeyPairType.DSA.toString()))
            {
                KeyFactory keyFact = KeyFactory.getInstance(sAlgorithm);
                DSAPublicKeySpec keySpec = (DSAPublicKeySpec)
                    keyFact.getKeySpec(pubKey, DSAPublicKeySpec.class);
                BigInteger prime = keySpec.getP();
                return prime.toString(2).length();
            }
            // Otherwise cannot calculate keysize
            else
            {
                throw new CryptoException(
                    MessageFormat.format(
                        m_res.getString(
                            "NoCertificatePublicKeysizeUnrecogAlg." +
                            "exception.message"),
                        new Object[]{sAlgorithm}));
            }
        }
        catch (GeneralSecurityException ex)
        {
            throw new CryptoException(
                m_res.getString(
                    "NoCertificatePublicKeysize.exception.message"), ex);
        }
    }
}
