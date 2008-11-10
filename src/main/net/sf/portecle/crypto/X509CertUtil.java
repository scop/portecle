/*
 * X509CertUtil.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004-2008 Ville Skyttä, ville.skytta@iki.fi
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package net.sf.portecle.crypto;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import net.sf.portecle.NetUtil;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.x509.X509V1CertificateGenerator;

/**
 * Provides utility methods relating to X509 Certificates, CRLs and CSRs.
 */
public final class X509CertUtil
{
	/** Logger */
	private static final Logger LOG = Logger.getLogger(X509CertUtil.class.getCanonicalName());

	/** PKCS #7 encoding name */
	private static final String PKCS7_ENCODING = "PKCS7";

	/** PkiPath encoding name */
	private static final String PKIPATH_ENCODING = "PkiPath";

	/** OpenSSL PEM encoding name */
	private static final String OPENSSL_PEM_ENCODING = "OpenSSL_PEM";

	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/crypto/resources");

	/** Type name for X.509 certificates */
	private static final String X509_CERT_TYPE = "X.509";

	/**
	 * Private to prevent construction.
	 */
	private X509CertUtil()
	{
	}

	/**
	 * Load one or more certificates from the specified URL, trying a built in list of certification
	 * encodings.
	 * 
	 * @param url The URL to load certificates from
	 * @param exceptions Collection where exceptions occurred will be added
	 * @return The certificates
	 * @throws IOException if an error accessing the URL occurs
	 */
	public static X509Certificate[] loadCertificates(URL url, Collection<Exception> exceptions)
	    throws IOException
	{
		URL downloadedUrl = NetUtil.download(url);

		X509Certificate[] certs = null;
		String[] certTypes = { PKCS7_ENCODING, PKIPATH_ENCODING, null, OPENSSL_PEM_ENCODING, };
		for (int iCnt = 0; iCnt < certTypes.length; iCnt++)
		{
			try
			{
				certs = loadCertificates(downloadedUrl, certTypes[iCnt]);
				break; // Success!
			}
			catch (FileNotFoundException e)
			{
				// Don't bother with rest of the types, just show the exception once
				exceptions.add(e);
				break;
			}
			catch (Exception e)
			{
				exceptions.add(e);
			}
		}

		return certs;
	}

	/**
	 * Load one or more certificates from the specified URL.
	 * 
	 * @param url The URL to load certificates from
	 * @param encoding The certification path encoding. If null, treat as a normal certificate, not
	 *            certification path. Use one of the <code>*_ENCODING</code> constants here.
	 * @return The certificates
	 * @throws CryptoException Problem encountered while loading the certificate(s)
	 * @throws FileNotFoundException If the certificate file does not exist, is a directory rather than a
	 *             regular file, or for some other reason cannot be opened for reading
	 * @throws IOException An I/O error occurred
	 */
	private static X509Certificate[] loadCertificates(URL url, String encoding)
	    throws CryptoException, IOException
	{
		// TODO: connect/read timeouts

		InputStream in = NetUtil.openGetStream(url);
		Collection certs;

		try
		{
			if (OPENSSL_PEM_ENCODING.equals(encoding))
			{

				// Special case; this is not a real JCE supported encoding.
				// Note: let PEMReader use its default provider (BC as of BC
				// 1.40) internally; for example the default "SUN" provider
				// may not contain an RSA implementation
				PEMReader pr = new PEMReader(new InputStreamReader(in));

				/*
				 * These beasts can contain just about anything, and unfortunately the PEMReader API (as of BC
				 * 1.25 to 1.40) won't allow us to really skip things we're not interested in; stuff happens
				 * already in readObject(). This may cause some weird exception messages for non-certificate
				 * objects in the "stream", for example passphrase related ones for protected private keys.
				 * Well, I guess this is better than nothing anyway... :(
				 */

				certs = new ArrayList();
				Object cert;

				/*
				 * Would be nice if there was a way to just skip objects whose decoding fails (see e.g. above
				 * for passphrase stuff), but as of BC 1.40, readObject() throws everything as IOException -
				 * we don't know if the problem was decoding (in which case we'd continue with the next
				 * object) or during "normal" stream read (in which case we'd abort) :/
				 */
				while ((cert = pr.readObject()) != null)
				{
					if (cert instanceof X509Certificate)
					{
						certs.add(cert);
					}
					// Skip other stuff, at least for now.
				}
				pr.close();
			}
			else
			{
				CertificateFactory cf = CertificateFactory.getInstance(X509_CERT_TYPE);

				if (encoding != null)
				{
					// Try it as a certification path of the specified type
					certs = cf.generateCertPath(in, encoding).getCertificates();
				}
				else
				{
					// "Normal" certificate(s)
					certs = cf.generateCertificates(in);
				}

				/*
				 * Note that we rely on cf.generateCert() above to never return null nor a collection
				 * containing nulls
				 */
			}
		}
		// Some RuntimeExceptions which really should be
		// CertificateExceptions may be thrown from cf.generateCert* above,
		// for example Sun's PKCS #7 parser tends to throw them... :P
		catch (Exception ex)
		{
			// TODO: don't throw if vCerts non-empty (eg. OpenSSL PEM above)?
			throw new CryptoException(m_res.getString("NoLoadCertificate.exception.message"), ex);
		}
		finally
		{
			try
			{
				in.close();
			}
			catch (IOException e)
			{
				LOG.log(Level.WARNING, "Could not close input stream from " + url, e);
			}
		}

		return (X509Certificate[]) certs.toArray(new X509Certificate[certs.size()]);
	}

	/**
	 * Load a CRL from the specified URL.
	 * 
	 * @param url The URL to load CRL from
	 * @return The CRL
	 * @throws CryptoException Problem encountered while loading the CRL
	 * @throws FileNotFoundException If the CRL file does not exist, is a directory rather than a regular
	 *             file, or for some other reason cannot be opened for reading
	 * @throws IOException An I/O error occurred
	 */
	public static X509CRL loadCRL(URL url)
	    throws CryptoException, IOException
	{
		InputStream in = NetUtil.openGetStream(url);
		try
		{
			CertificateFactory cf = CertificateFactory.getInstance(X509_CERT_TYPE);
			X509CRL crl = (X509CRL) cf.generateCRL(in);
			return crl;
		}
		catch (GeneralSecurityException ex)
		{
			throw new CryptoException(m_res.getString("NoLoadCrl.exception.message"), ex);
		}
		finally
		{
			try
			{
				in.close();
			}
			catch (IOException e)
			{
				LOG.log(Level.WARNING, "Could not close input stream from " + url, e);
			}
		}
	}

	/**
	 * Load a CSR from the specified URL.
	 * 
	 * @param url The URL to load CSR from
	 * @return The CSR
	 * @throws CryptoException Problem encountered while loading the CSR
	 * @throws FileNotFoundException If the CSR file does not exist, is a directory rather than a regular
	 *             file, or for some other reason cannot be opened for reading
	 * @throws IOException An I/O error occurred
	 */
	public static PKCS10CertificationRequest loadCSR(URL url)
	    throws CryptoException, IOException
	{
		// TODO: handle DER encoded requests too?
		PEMReader pr = new PEMReader(new InputStreamReader(NetUtil.openGetStream(url)));
		try
		{
			PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pr.readObject();
			if (!csr.verify())
			{
				throw new CryptoException(m_res.getString("NoVerifyCsr.exception.message"));
			}
			return csr;
		}
		catch (ClassCastException ex)
		{
			throw new CryptoException(m_res.getString("NoLoadCsr.exception.message"), ex);
		}
		catch (GeneralSecurityException ex)
		{
			throw new CryptoException(m_res.getString("NoLoadCsr.exception.message"), ex);
		}
		finally
		{
			try
			{
				pr.close();
			}
			catch (IOException e)
			{
				LOG.log(Level.WARNING, "Could not close input stream from " + url, e);
			}
		}
	}

	/**
	 * Convert the supplied array of certificate objects into X509Certificate objects.
	 * 
	 * @param certsIn The Certificate objects
	 * @return The converted X509Certificate objects
	 * @throws CryptoException A problem occurred during the conversion
	 */
	public static X509Certificate[] convertCertificates(Certificate[] certsIn)
	    throws CryptoException
	{
		X509Certificate[] certsOut = new X509Certificate[certsIn.length];

		for (int iCnt = 0; iCnt < certsIn.length; iCnt++)
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
			CertificateFactory cf = CertificateFactory.getInstance(X509_CERT_TYPE);
			ByteArrayInputStream bais = new ByteArrayInputStream(certIn.getEncoded());
			return (X509Certificate) cf.generateCertificate(bais);
		}
		catch (CertificateException ex)
		{
			throw new CryptoException(m_res.getString("NoConvertCertificate.exception.message"), ex);
		}
	}

	/**
	 * Attempt to order the supplied array of X.509 certificates in issued to to issued from order.
	 * 
	 * @param certs The X.509 certificates in order
	 * @return The ordered X.509 certificates
	 */
	public static X509Certificate[] orderX509CertChain(X509Certificate[] certs)
	{
		int iOrdered = 0;
		X509Certificate[] tmpCerts = certs.clone();
		X509Certificate[] orderedCerts = new X509Certificate[certs.length];

		X509Certificate issuerCert = null;

		// Find the root issuer (ie certificate where issuer is the same
		// as subject)
		for (X509Certificate aCert : tmpCerts)
		{
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
			for (X509Certificate aCert : tmpCerts)
			{
				// Is this certificate the next in the chain?
				if (aCert.getIssuerDN().equals(issuerCert.getSubjectDN()) && aCert != issuerCert)
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

		for (int iCnt = 0; iCnt < iOrdered; iCnt++)
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
			throw new CryptoException(m_res.getString("NoDerEncode.exception.message"), ex);
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
		return getCertsEncodedPkcs7(new X509Certificate[] { cert });
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
		return getCertsEncoded(certs, PKCS7_ENCODING, "NoPkcs7Encode.exception.message");
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
		return getCertsEncodedPkiPath(new X509Certificate[] { cert });
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
		return getCertsEncoded(certs, PKIPATH_ENCODING, "NoPkiPathEncode.exception.message");
	}

	/**
	 * Encode a number of certificates using the given encoding.
	 * 
	 * @return The encoded certificates
	 * @param certs The certificates
	 * @param encoding The encoding
	 * @param errkey The error message key to use in the possibly occurred exception
	 * @throws CryptoException If there was a problem encoding the certificates
	 */
	private static byte[] getCertsEncoded(X509Certificate[] certs, String encoding, String errkey)
	    throws CryptoException
	{
		try
		{
			CertificateFactory cf = CertificateFactory.getInstance(X509_CERT_TYPE);
			return cf.generateCertPath(Arrays.asList(certs)).getEncoded(encoding);
		}
		catch (CertificateException ex)
		{
			throw new CryptoException(m_res.getString(errkey), ex);
		}
	}

	/**
	 * Generate a self-signed X509 Version 1 certificate for the supplied key pair and signature algorithm.
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
	 * @throws CryptoException If there was a problem generating the certificate
	 */
	public static X509Certificate generateCert(String sCommonName, String sOrganisationUnit,
	    String sOrganisation, String sLocality, String sState, String sCountryCode, String sEmailAddress,
	    int iValidity, PublicKey publicKey, PrivateKey privateKey, SignatureType signatureType)
	    throws CryptoException
	{
		// Holds certificate attributes
		Hashtable<DERObjectIdentifier, String> attrs = new Hashtable<DERObjectIdentifier, String>();
		Vector<DERObjectIdentifier> vOrder = new Vector<DERObjectIdentifier>();

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
		certGen.setNotAfter(new Date(System.currentTimeMillis() + ((long) iValidity * 24 * 60 * 60 * 1000)));

		// Set the subject distinguished name (same as issuer for our purposes)
		certGen.setSubjectDN(new X509Principal(vOrder, attrs));

		// Set the public key
		certGen.setPublicKey(publicKey);

		// Set the algorithm
		certGen.setSignatureAlgorithm(signatureType.name());

		// Set the serial number
		certGen.setSerialNumber(generateX509SerialNumber());

		try
		{
			// Generate an X.509 certificate, based on the current issuer and
			// subject
			X509Certificate cert = certGen.generate(privateKey, "BC");

			// Return the certificate
			return cert;
		}
		// Something went wrong
		catch (GeneralSecurityException ex)
		{
			throw new CryptoException(m_res.getString("CertificateGenFailed.exception.message"), ex);
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
		return new BigInteger(Long.toString(System.currentTimeMillis() / 1000));
	}

	/**
	 * Create a PKCS #10 certification request (CSR) using the supplied certificate and private key.
	 * 
	 * @param cert The certificate
	 * @param privateKey The private key
	 * @throws CryptoException If there was a problem generating the CSR
	 * @return The CSR
	 */
	public static PKCS10CertificationRequest generatePKCS10CSR(X509Certificate cert, PrivateKey privateKey)
	    throws CryptoException
	{
		X509Name subject = new X509Name(cert.getSubjectDN().toString());

		try
		{
			PKCS10CertificationRequest csr =
			    new PKCS10CertificationRequest(cert.getSigAlgName(), subject, cert.getPublicKey(), null,
			        privateKey);
			if (!csr.verify())
			{
				throw new CryptoException(m_res.getString("NoVerifyGenCsr.exception.message"));
			}

			return csr;
		}
		catch (GeneralSecurityException ex)
		{
			throw new CryptoException(m_res.getString("NoGenerateCsr.exception.message"), ex);
		}
	}

	/**
	 * Verify that one X.509 certificate was signed using the private key that corresponds to the public key
	 * of a second certificate.
	 * 
	 * @return True if the first certificate was signed by private key corresponding to the second signature
	 * @param signedCert The signed certificate
	 * @param signingCert The signing certificate
	 * @throws CryptoException If there was a problem verifying the signature.
	 */
	public static boolean verifyCertificate(X509Certificate signedCert, X509Certificate signingCert)
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
			throw new CryptoException(m_res.getString("NoVerifyCertificate.exception.message"), ex);
		}
		return true;
	}

	/**
	 * Check whether or not a trust path exists between the supplied X.509 certificate and and the supplied
	 * keystores based on the trusted certificates contained therein, ie that a chain of trust exists between
	 * the supplied certificate and a self-signed trusted certificate in the keystores.
	 * 
	 * @return The trust chain, or null if trust could not be established
	 * @param cert The certificate
	 * @param keyStores The keystores
	 * @throws CryptoException If there is a problem establishing trust
	 */
	public static X509Certificate[] establishTrust(KeyStore[] keyStores, X509Certificate cert)
	    throws CryptoException
	{
		// Extract all certificates from the Keystores creating
		ArrayList<X509Certificate> ksCerts = new ArrayList<X509Certificate>();
		for (KeyStore ks : keyStores)
		{
			ksCerts.addAll(extractCertificates(ks));
		}

		// Try and establish trust against the set of all certificates
		return establishTrust(ksCerts, cert);
	}

	/**
	 * Check whether or not a trust path exists between the supplied X.509 certificate and and the supplied
	 * comparison certificates based on the trusted certificates contained therein, ie that a chain of trust
	 * exists between the supplied certificate and a self-signed trusted certificate in the comparison set.
	 * 
	 * @return The trust chain, or null if trust could not be established
	 * @param cert The certificate
	 * @param vCompCerts The comparison set of certificates
	 * @throws CryptoException If there is a problem establishing trust
	 */
	private static X509Certificate[] establishTrust(List<X509Certificate> vCompCerts, X509Certificate cert)
	    throws CryptoException
	{
		// For each comparison certificate...
		for (X509Certificate compCert : vCompCerts)
		{
			// Check if the Comparison certificate's subject is the same as the
			// certificate's issuer
			if (cert.getIssuerDN().equals(compCert.getSubjectDN()))
			{
				// If so verify with the comparison certificate's corresponding
				// private key was used to sign the certificate
				if (X509CertUtil.verifyCertificate(cert, compCert))
				{
					// If the keystore certificate is self-signed then a
					// chain of trust exists
					if (compCert.getSubjectDN().equals(compCert.getIssuerDN()))
					{
						return new X509Certificate[] { cert, compCert };
					}
					// Otherwise try and establish a chain of trust for
					// the comparison certificate against the other comparison
					// certificates
					X509Certificate[] tmpChain = establishTrust(vCompCerts, compCert);
					if (tmpChain != null)
					{
						X509Certificate[] trustChain = new X509Certificate[tmpChain.length + 1];
						trustChain[0] = cert;
						System.arraycopy(tmpChain, 0, trustChain, 1, tmpChain.length);
						return trustChain;
					}
				}
			}
		}

		// No chain of trust
		return null;
	}

	/**
	 * Extract a copy of all trusted certificates contained within the supplied keystore.
	 * 
	 * @param keyStore The keystore
	 * @return The extracted certificates
	 * @throws CryptoException If a problem is encountered extracting the certificates
	 */
	private static Collection<X509Certificate> extractCertificates(KeyStore keyStore)
	    throws CryptoException
	{
		try
		{
			ArrayList<X509Certificate> vCerts = new ArrayList<X509Certificate>();

			for (Enumeration<String> en = keyStore.aliases(); en.hasMoreElements();)
			{
				String sAlias = en.nextElement();
				if (keyStore.isCertificateEntry(sAlias))
				{
					vCerts.add(X509CertUtil.convertCertificate(keyStore.getCertificate(sAlias)));
				}
			}

			return vCerts;
		}
		catch (KeyStoreException ex)
		{
			throw new CryptoException(m_res.getString("NoExtractCertificates.exception.message"), ex);
		}
	}

	/**
	 * Check whether or not a trusted certificate in the supplied keystore matches the the supplied X.509
	 * certificate.
	 * 
	 * @return The alias of the matching certificate in the keystore or null if there is no match
	 * @param cert The certificate
	 * @param keyStore The keystore
	 * @throws CryptoException If there is a problem establishing trust
	 */
	public static String matchCertificate(KeyStore keyStore, X509Certificate cert)
	    throws CryptoException
	{
		try
		{
			for (Enumeration<String> en = keyStore.aliases(); en.hasMoreElements();)
			{
				String sAlias = en.nextElement();
				if (keyStore.isCertificateEntry(sAlias))
				{
					X509Certificate compCert =
					    X509CertUtil.convertCertificate(keyStore.getCertificate(sAlias));

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
			throw new CryptoException(m_res.getString("NoMatchCertificate.exception.message"), ex);
		}
	}

	/**
	 * For a given X.509 certificate get a representative alias for it in a keystore. For a self-signed
	 * certificate this will be the subject's common name (if any). For a non-self-signed certificate it will
	 * be the subject's common name followed by the issuer's common name in parenthesis.
	 * 
	 * @param cert The certificate
	 * @return The alias or a blank string if none could be worked out
	 */
	public static String getCertificateAlias(X509Certificate cert)
	{
		X500Principal subject = cert.getSubjectX500Principal();
		X500Principal issuer = cert.getIssuerX500Principal();

		String sSubjectCN = NameUtil.getCommonName(subject);

		// Could not get a subject CN - return blank
		if (sSubjectCN == null)
		{
			return "";
		}

		String sIssuerCN = NameUtil.getCommonName(issuer);

		// Self-signed certificate or could not get an issuer CN
		if (subject.equals(issuer) || sIssuerCN == null)
		{
			// Alias is the subject CN
			return sSubjectCN;
		}
		// else non-self-signed certificate
		// Alias is the subject CN followed by the issuer CN in parenthesis
		return MessageFormat.format("{0} ({1})", sSubjectCN, sIssuerCN);
	}
}
