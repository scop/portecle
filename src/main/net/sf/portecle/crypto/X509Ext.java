/*
 * X509Ext.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004-2007 Ville Skyttä, ville.skytta@iki.fi
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
import java.io.IOException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.text.DateFormat;
import java.text.MessageFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.microsoft.MicrosoftObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapabilities;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;

/**
 * Holds the information of an X.509 extension and provides the ability to get the extension's name and value
 * as a string.
 */
public class X509Ext
{
	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/crypto/resources");

	// ///////////////////////////////////////////
	// Extension OIDs
	// ///////////////////////////////////////////

	/** Authority Key Identifier (old) OID */
	// private static final String AUTHORITY_KEY_IDENTIFIER_OLD_OID = "2.5.29.1";
	/** Primary Key Attributes OID */
	// No info available
	// private static final String PRIMARY_KEY_ATTRIBUTES_OID = "2.5.29.2";
	/** Certificate Policies (old) OID */
	// private static final String CERTIFICATE_POLICIES_OLD_OID = "2.5.29.3";
	/** Primary Key Usage Restriction (old) OID */
	// Old - not to do?
	// private static final String PRIMARY_KEY_USAGE_RESTRICTION_OID = "2.5.29.4";
	/** Subject Directory Attributes OID */
	// Std todo
	// private static final String SUBJECT_DIRECTORY_ATTRIBUTES_OID = "2.5.29.9";
	/** Basic Constraints (old 0) OID */
	// private static final String BASIC_CONSTRAINTS_OLD_0_OID = "2.5.29.10";
	/** Basic Constraints (old 1) OID */
	// Old - not to do?
	// private static final String BASIC_CONSTRAINTS_OLD_1_OID = "2.5.29.13";
	/** CRL Distribution Points (old) OID */
	// Old - not to do?
	// private static final String CRL_DISTRIBUTION_POINTS_OLD_OID = "2.5.29.25";
	/** Issuing Distribution Point OID */
	// Std todo
	// private static final String ISSUING_DISTRIBUTION_POINT_OID = "2.5.29.28";
	/** Name Constraints OID */
	// Std todo
	// private static final String NAME_CONSTRAINTS_OID = "2.5.29.30";
	/** Policy Constraints (old) OID */
	// Old - not to do?
	// private static final String POLICY_CONSTRAINTS_OLD_OID = "2.5.29.34";
	/** CRL Stream Identifier OID */
	// No info available
	// private static final String CRL_STREAM_IDENTIFIER_OID = "2.5.29.40";
	/** CRL Scope OID */
	// No info available
	// private static final String CRL_SCOPE_OID = "2.5.29.44";
	/** Status Referrals OID */
	// No info available
	// private static final String STATUS_REFERRALS_OID = "2.5.29.45";
	/** Freshest CRL OID */
	// Std todo
	// private static final String FRESHEST_CRL_OID = "2.5.29.46";
	/** Ordered List OID */
	// No info available
	// private static final String ORDERED_LIST_OID = "2.5.29.47";
	/** Base Update Time OID */
	// No info available
	// private static final String BASE_UPDATE_TIME_OID = "2.5.29.51";
	/** Delta Information OID */
	// No info available
	// private static final String DELTA_INFORMATION_OID = "2.5.29.53";
	/** Extension name or OID if unknown */
	private final String m_sName;

	/** Extension object identifier */
	private final DERObjectIdentifier m_Oid;

	/** Extension value as a DER-encoded OCTET string */
	private final byte[] m_bValue;

	/** Critical extension? */
	private final boolean m_bCritical;

	/**
	 * Construct a new immutable X509Ext.
	 * 
	 * @param sOid Extension object identifier
	 * @param bValue Extension value as a DER-encoded OCTET string
	 * @param bCritical Critical extension?
	 */
	public X509Ext(String sOid, byte[] bValue, boolean bCritical)
	{
		m_Oid = new DERObjectIdentifier(sOid);

		m_bValue = new byte[bValue.length];
		System.arraycopy(bValue, 0, m_bValue, 0, bValue.length);

		m_bCritical = bCritical;

		m_sName = getRes(m_Oid.getId(), "UnrecognisedExtension");
	}

	/**
	 * Get extension object identifier.
	 * 
	 * @return Extension object identifier
	 */
	public String getOid()
	{
		return m_Oid.getId();
	}

	/**
	 * Get extension value as a DER-encoded OCTET string.
	 * 
	 * @return Extension value
	 */
	public byte[] getValue()
	{
		byte[] bValue = new byte[m_bValue.length];
		System.arraycopy(m_bValue, 0, bValue, 0, m_bValue.length);
		return bValue;
	}

	/**
	 * Is extension critical?
	 * 
	 * @return True if is, false otherwise
	 */
	public boolean isCriticalExtension()
	{
		return m_bCritical;
	}

	/**
	 * Get extension name.
	 * 
	 * @return Extension name or null if unknown
	 */
	public String getName()
	{
		return m_sName;
	}

	/**
	 * Get extension value as a string.
	 * 
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 * @throws ParseException If a date formatting problem occurs
	 */
	public String getStringValue()
	    throws IOException, ParseException
	{
		// Get octet string from extension
		byte[] bOctets = ((ASN1OctetString) ASN1Object.fromByteArray(m_bValue)).getOctets();

		// Octet string processed differently depending on extension type
		if (m_Oid.equals(X509Name.CN))
		{
			return getCommonNameStringValue(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.SubjectKeyIdentifier))
		{
			return getSubjectKeyIndentifierStringValue(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.KeyUsage))
		{
			return getKeyUsageStringValue(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.PrivateKeyUsagePeriod))
		{
			return getPrivateKeyUsagePeriod(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.SubjectAlternativeName))
		{
			return getSubjectAlternativeName(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.IssuerAlternativeName))
		{
			return getIssuerAlternativeName(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.BasicConstraints))
		{
			return getBasicConstraintsStringValue(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.CRLNumber))
		{
			return getCrlNumberStringValue(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.ReasonCode))
		{
			return getReasonCodeStringValue(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.InstructionCode))
		{
			return getHoldInstructionCodeStringValue(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.InvalidityDate))
		{
			return getInvalidityDateStringValue(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.DeltaCRLIndicator))
		{
			return getDeltaCrlIndicatorStringValue(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.CertificateIssuer))
		{
			return getCertificateIssuerStringValue(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.PolicyMappings))
		{
			return getPolicyMappingsStringValue(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.AuthorityKeyIdentifier))
		{
			return getAuthorityKeyIdentifierStringValue(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.PolicyConstraints))
		{
			return getPolicyConstraintsStringValue(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.ExtendedKeyUsage))
		{
			return getExtendedKeyUsageStringValue(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.InhibitAnyPolicy))
		{
			return getInhibitAnyPolicyStringValue(bOctets);
		}
		else if (m_Oid.equals(MiscObjectIdentifiers.entrustVersionExtension))
		{
			return getEntrustVersionExtensionStringValue(bOctets);
		}
		else if (m_Oid.equals(PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities))
		{
			return getSmimeCapabilitiesStringValue(bOctets);
		}
		else if (m_Oid.equals(MicrosoftObjectIdentifiers.microsoftCertTemplateV1))
		{
			return getMicrosoftCertificateTemplateV1StringValue(bOctets);
		}
		else if (m_Oid.equals(MicrosoftObjectIdentifiers.microsoftCaVersion))
		{
			return getMicrosoftCAVersionStringValue(bOctets);
		}
		else if (m_Oid.equals(MicrosoftObjectIdentifiers.microsoftPrevCaCertHash))
		{
			return getMicrosoftPreviousCACertificateHashStringValue(bOctets);
		}
		else if (m_Oid.equals(MicrosoftObjectIdentifiers.microsoftCertTemplateV2))
		{
			return getMicrosoftCertificateTemplateV2StringValue(bOctets);
		}
		else if (m_Oid.equals(MicrosoftObjectIdentifiers.microsoftAppPolicies))
		{
			return getUnknownOidStringValue(bOctets); // TODO
		}
		else if (m_Oid.equals(X509Extensions.AuthorityInfoAccess) ||
		    m_Oid.equals(X509Extensions.SubjectInfoAccess))
		{
			return getInformationAccessStringValue(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.LogoType))
		{
			return getLogotypeStringValue(bOctets);
		}
		else if (m_Oid.equals(MiscObjectIdentifiers.novellSecurityAttribs))
		{
			return getNovellSecurityAttributesStringValue(bOctets);
		}
		else if (m_Oid.equals(MiscObjectIdentifiers.netscapeCertType))
		{
			return getNetscapeCertificateTypeStringValue(bOctets);
		}
		else if (m_Oid.equals(MiscObjectIdentifiers.netscapeBaseURL) ||
		    m_Oid.equals(MiscObjectIdentifiers.netscapeRevocationURL) ||
		    m_Oid.equals(MiscObjectIdentifiers.netscapeCARevocationURL) ||
		    m_Oid.equals(MiscObjectIdentifiers.netscapeRenewalURL) ||
		    m_Oid.equals(MiscObjectIdentifiers.netscapeCApolicyURL) ||
		    m_Oid.equals(MiscObjectIdentifiers.netscapeSSLServerName) ||
		    m_Oid.equals(MiscObjectIdentifiers.netscapeCertComment))
		{
			return getNonNetscapeCertificateTypeStringValue(bOctets);
		}
		else if (m_Oid.equals(MiscObjectIdentifiers.verisignDnbDunsNumber))
		{
			return getDnBDUNSNumberStringValue(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.CRLDistributionPoints))
		{
			return getCrlDistributionPointsStringValue(bOctets);
		}
		else if (m_Oid.equals(X509Extensions.CertificatePolicies))
		{
			return getCertificatePoliciesStringValue(bOctets);
		}

		// TODO:
		// - CERTIFICATE_POLICIES_OLD_OID
		// - AUTHORITY_KEY_IDENTIFIER_OLD_OID
		// - BASIC_CONSTRAINTS_OLD_0_OID

		// Don't know how to process the extension
		// and clear text
		else
		{
			return getUnknownOidStringValue(bOctets);
		}
	}

	/**
	 * Get unknown OID extension value as a string.
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string (hex/clear text dump)
	 * @throws IOException If an I/O error occurs
	 */
	private String getUnknownOidStringValue(byte[] bValue)
	    throws IOException
	{
		ByteArrayInputStream bais = null;
		int nBytes = 16; // how many bytes to show per line

		try
		{
			// Divide dump into 16 byte lines
			StringBuilder strBuff = new StringBuilder();

			bais = new ByteArrayInputStream(bValue);
			byte[] bLine = new byte[nBytes];
			int iRead = -1;

			while ((iRead = bais.read(bLine)) != -1)
			{
				strBuff.append(getHexClearDump(bLine, iRead));
			}

			return strBuff.toString();
		}
		finally
		{
			try
			{
				if (bais != null)
					bais.close();
			}
			catch (IOException ex)
			{ /* Ignore */
			}
		}
	}

	/**
	 * Get Common Name (2.5.4.3) extension value as a string.
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getCommonNameStringValue(byte[] bValue)
	    throws IOException
	{
		return stringify(ASN1Object.fromByteArray(bValue));
	}

	/**
	 * Get Subject Key Indentifier (2.5.29.14) extension value as a string.
	 * 
	 * <pre>
	 * SubjectKeyIdentifier ::= KeyIdentifier
	 * KeyIdentifier ::= OCTET STRING
	 * </pre>
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getSubjectKeyIndentifierStringValue(byte[] bValue)
	    throws IOException
	{
		SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(ASN1Object.fromByteArray(bValue));
		byte[] bKeyIdent = ski.getKeyIdentifier();

		// Output as a hex string
		StringBuilder strBuff = new StringBuilder();
		strBuff.append(convertToHexString(bKeyIdent));
		strBuff.append('\n');
		return strBuff.toString();
	}

	/** Key usages */
	private static final int[] KEY_USAGES =
	    new int[] { KeyUsage.digitalSignature, KeyUsage.nonRepudiation, KeyUsage.keyEncipherment,
	        KeyUsage.dataEncipherment, KeyUsage.keyAgreement, KeyUsage.keyCertSign, KeyUsage.cRLSign,
	        KeyUsage.encipherOnly, KeyUsage.decipherOnly, };

	/**
	 * Get Key Usage (2.5.29.15) extension value as a string.
	 * 
	 * <pre>
	 * KeyUsage ::= BIT STRING {
	 *     digitalSignature        (0),
	 *     nonRepudiation          (1),
	 *     keyEncipherment         (2),
	 *     dataEncipherment        (3),
	 *     keyAgreement            (4),
	 *     keyCertSign             (5),
	 *     cRLSign                 (6),
	 *     encipherOnly            (7),
	 *     decipherOnly            (8) }
	 * </pre>
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getKeyUsageStringValue(byte[] bValue)
	    throws IOException
	{
		int val = KeyUsage.getInstance(ASN1Object.fromByteArray(bValue)).intValue();
		StringBuilder strBuff = new StringBuilder();
		for (int type : KEY_USAGES)
		{
			if ((val & type) == type)
			{
				strBuff.append(m_res.getString("KeyUsage." + type));
				strBuff.append('\n');
			}
		}
		return strBuff.toString();
	}

	/**
	 * Get Private Key Usage Period (2.5.29.16) extension value as a string.
	 * 
	 * <pre>
	 * PrivateKeyUsagePeriod ::= SEQUENCE {
	 *       notBefore       [0]     GeneralizedTime OPTIONAL,
	 *       notAfter        [1]     GeneralizedTime OPTIONAL }
	 * </pre>
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 * @throws ParseException If a date formatting problem occurs
	 */
	private String getPrivateKeyUsagePeriod(byte[] bValue)
	    throws IOException, ParseException
	{
		PrivateKeyUsagePeriod pkup = PrivateKeyUsagePeriod.getInstance(ASN1Object.fromByteArray(bValue));

		StringBuilder strBuff = new StringBuilder();
		DERGeneralizedTime dTime;

		if ((dTime = pkup.getNotBefore()) != null)
		{
			strBuff.append(MessageFormat.format(m_res.getString("PrivateKeyUsagePeriodNotBefore"),
			    formatGeneralizedTime(dTime)));
			strBuff.append('\n');
		}

		if ((dTime = pkup.getNotAfter()) != null)
		{
			strBuff.append(MessageFormat.format(m_res.getString("PrivateKeyUsagePeriodNotAfter"),
			    formatGeneralizedTime(dTime)));
			strBuff.append('\n');
		}

		return strBuff.toString();
	}

	/**
	 * Get Subject Alternative Name (2.5.29.17) extension value as a string.
	 * 
	 * <pre>
	 * SubjectAltName ::= GeneralNames
	 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	 * </pre>
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getSubjectAlternativeName(byte[] bValue)
	    throws IOException
	{
		return getGeneralNamesString(GeneralNames.getInstance(ASN1Object.fromByteArray(bValue)), "");
	}

	/**
	 * Get Issuer Alternative Name (2.5.29.18) extension value as a string.
	 * 
	 * <pre>
	 * SubjectAltName ::= GeneralNames
	 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	 * </pre>
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getIssuerAlternativeName(byte[] bValue)
	    throws IOException
	{
		return getGeneralNamesString(GeneralNames.getInstance(ASN1Object.fromByteArray(bValue)), "");
	}

	/**
	 * Get Basic Constraints (2.5.29.19) extension value as a string.
	 * 
	 * <pre>
	 * BasicConstraints ::= SEQUENCE {
	 *     cA                      BOOLEAN DEFAULT FALSE,
	 *     pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
	 * </pre>
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getBasicConstraintsStringValue(byte[] bValue)
	    throws IOException
	{
		BasicConstraints bc = BasicConstraints.getInstance(ASN1Object.fromByteArray(bValue));
		StringBuilder strBuff = new StringBuilder();

		strBuff.append(m_res.getString(bc.isCA() ? "SubjectIsCa" : "SubjectIsNotCa"));
		strBuff.append('\n');

		BigInteger pathLen = bc.isCA() ? bc.getPathLenConstraint() : null;
		if (pathLen == null)
		{
			strBuff.append(m_res.getString("NoPathLengthConstraint"));
		}
		else
		{
			strBuff.append(MessageFormat.format(m_res.getString("PathLengthConstraint"), pathLen));
		}

		return strBuff.append('\n').toString();
	}

	/**
	 * Get CRL Number (2.5.29.20) extension value as a string.
	 * 
	 * <pre>
	 * CRLNumber ::= INTEGER (0..MAX)
	 * </pre>
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getCrlNumberStringValue(byte[] bValue)
	    throws IOException
	{
		// Get CRL number
		DERInteger derInt = (DERInteger) ASN1Object.fromByteArray(bValue);

		// Convert to and return hex string representation of number
		StringBuilder strBuff = new StringBuilder();
		strBuff.append(convertToHexString(derInt));
		strBuff.append('\n');
		return strBuff.toString();
	}

	/**
	 * Get Reason Code (2.5.29.21) extension value as a string.
	 * 
	 * <pre>
	 * ReasonCode ::= { CRLReason }
	 * CRLReason ::= ENUMERATED {
	 *     unspecified             (0),
	 *     keyCompromise           (1),
	 *     cACompromise            (2),
	 *     affiliationChanged      (3),
	 *     superseded              (4),
	 *     cessationOfOperation    (5),
	 *     certificateHold         (6),
	 *     removeFromCRL           (8),
	 *     privilegeWithdrawn      (9),
	 *     aACompromise           (10) }
	 * </pre>
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getReasonCodeStringValue(byte[] bValue)
	    throws IOException
	{
		int iRc = ((DEREnumerated) ASN1Object.fromByteArray(bValue)).getValue().intValue();
		String sRc = getRes("CrlReason." + iRc, "UnrecognisedCrlReasonString");
		return MessageFormat.format(sRc, iRc) + '\n';
	}

	/**
	 * Get Hold Instruction Code (2.5.29.23) extension value as a string.
	 * 
	 * <pre>
	 * HoldInstructionCode ::= OBJECT IDENTIFER
	 * </pre>
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getHoldInstructionCodeStringValue(byte[] bValue)
	    throws IOException
	{
		String sHoldIns = ASN1Object.fromByteArray(bValue).toString();
		String res = getRes(sHoldIns, "UnrecognisedHoldInstructionCode");
		return MessageFormat.format(res, sHoldIns) + '\n';
	}

	/**
	 * Get Invalidity Date (2.5.29.24) extension value as a string.
	 * 
	 * <pre>
	 * InvalidityDate ::=  GeneralizedTime
	 * </pre>
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 * @throws ParseException If a date formatting problem occurs
	 */
	private String getInvalidityDateStringValue(byte[] bValue)
	    throws IOException, ParseException
	{
		// Get invalidity date
		DERGeneralizedTime invalidityDate = (DERGeneralizedTime) ASN1Object.fromByteArray(bValue);

		// Format invalidity date for display
		String sInvalidityTime = formatGeneralizedTime(invalidityDate);

		StringBuilder strBuff = new StringBuilder();
		strBuff.append(sInvalidityTime);
		strBuff.append('\n');
		return strBuff.toString();
	}

	/**
	 * Get Delta CRL Indicator (2.5.29.27) extension value as a string.
	 * 
	 * <pre>
	 * BaseCRLNumber ::= CRLNumber
	 * CRLNumber ::= INTEGER (0..MAX)
	 * </pre>
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getDeltaCrlIndicatorStringValue(byte[] bValue)
	    throws IOException
	{
		// Get CRL number
		DERInteger derInt = (DERInteger) ASN1Object.fromByteArray(bValue);

		// Convert to and return hex string representation of number
		StringBuilder strBuff = new StringBuilder();
		strBuff.append(convertToHexString(derInt));
		strBuff.append('\n');
		return strBuff.toString();
	}

	/**
	 * Get Certificate Issuer (2.5.29.29) extension value as a string.
	 * 
	 * <pre>
	 * certificateIssuer ::= GeneralNames
	 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	 * </pre>
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getCertificateIssuerStringValue(byte[] bValue)
	    throws IOException
	{
		return getGeneralNamesString(GeneralNames.getInstance(ASN1Object.fromByteArray(bValue)), "");
	}

	/**
	 * Get Policy Mappings (2.5.29.33) extension value as a string.
	 * 
	 * <pre>
	 * PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
	 *     issuerDomainPolicy      CertPolicyId,
	 *      subjectDomainPolicy     CertPolicyId }
	 * CertPolicyId ::= OBJECT IDENTIFIER
	 * </pre>
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getPolicyMappingsStringValue(byte[] bValue)
	    throws IOException
	{
		// Get sequence of policy mappings
		ASN1Sequence policyMappings = (ASN1Sequence) ASN1Object.fromByteArray(bValue);

		StringBuilder strBuff = new StringBuilder();

		// Get each policy mapping
		for (int i = 0, len = policyMappings.size(); i < len; i++)
		{
			ASN1Sequence policyMapping = (ASN1Sequence) policyMappings.getObjectAt(i);
			int pmLen = policyMapping.size();

			strBuff.append(MessageFormat.format(m_res.getString("PolicyMapping"), i + 1));
			strBuff.append('\n');

			if (pmLen > 0)
			{ // Policy mapping issuer domain policy
				DERObjectIdentifier issuerDomainPolicy = (DERObjectIdentifier) policyMapping.getObjectAt(0);
				strBuff.append('\t');
				strBuff.append(MessageFormat.format(m_res.getString("IssuerDomainPolicy"),
				    issuerDomainPolicy.getId()));
				strBuff.append('\n');
			}

			if (pmLen > 1)
			{ // Policy mapping subject domain policy
				DERObjectIdentifier subjectDomainPolicy = (DERObjectIdentifier) policyMapping.getObjectAt(1);
				strBuff.append('\t');
				strBuff.append(MessageFormat.format(m_res.getString("SubjectDomainPolicy"),
				    subjectDomainPolicy.getId()));
				strBuff.append('\n');
			}
		}

		return strBuff.toString();
	}

	/**
	 * Get Authority Key Identifier (2.5.29.35) extension value as a string.
	 * 
	 * <pre>
	 * AuthorityKeyIdentifier ::= SEQUENCE {
	 *     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
	 *     authorityCertIssuer       [1] Names                   OPTIONAL,
	 *     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL }
	 * KeyIdentifier ::= OCTET STRING
	 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	 * CertificateSerialNumber  ::=  INTEGER
	 * </pre>
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getAuthorityKeyIdentifierStringValue(byte[] bValue)
	    throws IOException
	{
		AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(ASN1Object.fromByteArray(bValue));

		StringBuilder strBuff = new StringBuilder();

		byte[] keyIdentifier = aki.getKeyIdentifier();
		if (keyIdentifier != null)
		{
			strBuff.append(MessageFormat.format(m_res.getString("KeyIdentifier"),
			    convertToHexString(keyIdentifier)));
			strBuff.append('\n');
		}

		GeneralNames authorityCertIssuer;
		if ((authorityCertIssuer = aki.getAuthorityCertIssuer()) != null)
		{
			strBuff.append(m_res.getString("CertificateIssuer"));
			strBuff.append('\n');
			strBuff.append(getGeneralNamesString(authorityCertIssuer, "\t"));
		}

		BigInteger serialNo;
		if ((serialNo = aki.getAuthorityCertSerialNumber()) != null)
		{
			strBuff.append(MessageFormat.format(m_res.getString("CertificateSerialNumber"), serialNo));
			strBuff.append('\n');
		}

		return strBuff.toString();
	}

	/**
	 * Get Policy Constraints (2.5.29.36) extension value as a string.
	 * 
	 * <pre>
	 * PolicyConstraints ::= SEQUENCE {
	 *     requireExplicitPolicy           [0] SkipCerts OPTIONAL,
	 *     inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
	 * SkipCerts ::= INTEGER (0..MAX)
	 * </pre>
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getPolicyConstraintsStringValue(byte[] bValue)
	    throws IOException
	{
		// Get sequence of policy constraint
		ASN1Sequence policyConstraints = (ASN1Sequence) ASN1Object.fromByteArray(bValue);

		StringBuilder strBuff = new StringBuilder();

		for (int i = 0, len = policyConstraints.size(); i < len; i++)
		{
			DERTaggedObject policyConstraint = (DERTaggedObject) policyConstraints.getObjectAt(i);
			DERInteger skipCerts =
			    new DERInteger(((DEROctetString) policyConstraint.getObject()).getOctets());
			int iSkipCerts = skipCerts.getValue().intValue();

			switch (policyConstraint.getTagNo())
			{
				case 0: // Require Explicit Policy Skip Certs
					strBuff.append(MessageFormat.format(m_res.getString("RequireExplicitPolicy"), iSkipCerts));
					strBuff.append('\n');
					break;
				case 1: // Inhibit Policy Mapping Skip Certs
					strBuff.append(MessageFormat.format(m_res.getString("InhibitPolicyMapping"), iSkipCerts));
					strBuff.append('\n');
					break;
			}
		}

		return strBuff.toString();

	}

	/**
	 * Get Extended Key Usage (2.5.29.37) extension value as a string.
	 * 
	 * <pre>
	 * ExtendedKeyUsage ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
	 * KeyPurposeId ::= OBJECT IDENTIFIER
	 * </pre>
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getExtendedKeyUsageStringValue(byte[] bValue)
	    throws IOException
	{
		// Get sequence of OIDs and return approriate strings
		ASN1Sequence asn1Seq = (ASN1Sequence) ASN1Object.fromByteArray(bValue);

		StringBuilder strBuff = new StringBuilder();

		for (int i = 0, len = asn1Seq.size(); i < len; i++)
		{
			String sOid = ((DERObjectIdentifier) asn1Seq.getObjectAt(i)).getId();
			String sEku = getRes(sOid, "UnrecognisedExtKeyUsageString");
			strBuff.append(MessageFormat.format(sEku, sOid));
			strBuff.append('\n');
		}

		return strBuff.toString();
	}

	/**
	 * Get Inhibit Any Policy (2.5.29.54) extension value as a string.
	 * 
	 * <pre>
	 * InhibitAnyPolicy ::= SkipCerts
	 * SkipCerts ::= INTEGER (0..MAX)
	 * </pre>
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getInhibitAnyPolicyStringValue(byte[] bValue)
	    throws IOException
	{
		// Get skip certs integer
		DERInteger skipCerts = (DERInteger) ASN1Object.fromByteArray(bValue);

		int iSkipCerts = skipCerts.getValue().intValue();

		// Return inhibit any policy extension
		StringBuilder strBuff = new StringBuilder();
		strBuff.append(MessageFormat.format(m_res.getString("InhibitAnyPolicy"), iSkipCerts));
		strBuff.append('\n');
		return strBuff.toString();
	}

	/**
	 * Get Entrust Version Extension (1.2.840.113533.7.65.0) extension value as a string.
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getEntrustVersionExtensionStringValue(byte[] bValue)
	    throws IOException
	{
		// SEQUENCE encapsulated in a OCTET STRING
		ASN1Sequence as = (ASN1Sequence) ASN1Object.fromByteArray(bValue);
		// Also has BIT STRING, ignored here
		// http://www.mail-archive.com/openssl-dev@openssl.org/msg06546.html
		return ((DERGeneralString) as.getObjectAt(0)).getString();
	}

	/**
	 * Get Microsoft certificate template name V1 (1.3.6.1.4.1.311.20.2) extension value as a string.
	 * 
	 * @see <a href="http://support.microsoft.com/?kbid=291010">Microsoft KB article 291010</a>
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If and I/O problem occurs
	 */
	private String getMicrosoftCertificateTemplateV1StringValue(byte[] bValue)
	    throws IOException
	{
		return ((DERBMPString) ASN1Object.fromByteArray(bValue)).getString() + '\n';
	}

	/**
	 * Get Microsoft certificate template name V2 (1.3.6.1.4.1.311.20.7) extension value as a string.
	 * 
	 * <pre>
	 * CertificateTemplate ::= SEQUENCE {
	 *   templateID OBJECT IDENTIFIER,
	 *   templateMajorVersion TemplateVersion,
	 *   templateMinorVersion TemplateVersion OPTIONAL
	 * }
	 * TemplateVersion ::= INTEGER (0..4294967295)
	 * </pre>
	 * 
	 * @see <a
	 *      href="http://groups.google.com/groups?selm=OXFILYELDHA.1908%40TK2MSFTNGP11.phx.gbl">http://groups.google.com/groups?selm=OXFILYELDHA.1908%40TK2MSFTNGP11.phx.gbl</a>
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If and I/O problem occurs
	 */
	private String getMicrosoftCertificateTemplateV2StringValue(byte[] bValue)
	    throws IOException
	{
		ASN1Sequence seq = (ASN1Sequence) ASN1Object.fromByteArray(bValue);
		StringBuilder sb = new StringBuilder();

		sb.append(MessageFormat.format(m_res.getString("MsftCertTemplateId"),
		    ((DERObjectIdentifier) seq.getObjectAt(0)).getId()));
		sb.append('\n');

		DERInteger derInt = (DERInteger) seq.getObjectAt(1);
		sb.append(MessageFormat.format(m_res.getString("MsftCertTemplateMajorVer"), derInt.getValue()));
		sb.append('\n');

		if ((derInt = (DERInteger) seq.getObjectAt(2)) != null)
		{
			sb.append(MessageFormat.format(m_res.getString("MsftCertTemplateMinorVer"), derInt.getValue()));
			sb.append('\n');
		}

		return sb.toString();
	}

	/**
	 * Get Microsoft CA Version (1.3.6.1.4.1.311.21.1) extension value as a string.
	 * 
	 * @see <a
	 *      href="http://msdn.microsoft.com/library/en-us/security/security/certification_authority_renewal.asp">MSDN</a>
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If and I/O problem occurs
	 */
	private String getMicrosoftCAVersionStringValue(byte[] bValue)
	    throws IOException
	{
		int ver = ((DERInteger) ASN1Object.fromByteArray(bValue)).getValue().intValue();
		String certIx = String.valueOf(ver & 0xffff); // low 16 bits
		String keyIx = String.valueOf(ver >> 16); // high 16 bits
		return MessageFormat.format(m_res.getString("MsftCaVersion"), certIx, keyIx) + '\n';
	}

	/**
	 * Get Microsoft Previous CA Certificate Hash (1.3.6.1.4.1.311.21.2) extension value as a string.
	 * 
	 * @see <a href="http://support.microsoft.com/?id=287547">Microsoft support</a>
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If and I/O problem occurs
	 */
	private String getMicrosoftPreviousCACertificateHashStringValue(byte[] bValue)
	    throws IOException
	{
		DEROctetString derOctetStr = (DEROctetString) ASN1Object.fromByteArray(bValue);
		byte[] bKeyIdent = derOctetStr.getOctets();
		StringBuilder strBuff = new StringBuilder();
		return strBuff.append(convertToHexString(bKeyIdent)).append('\n').toString();
	}

	/**
	 * Get S/MIME capabilities (1.2.840.113549.1.9.15) extension value as a string.
	 * 
	 * <pre>
	 * SMIMECapability ::= SEQUENCE {
	 *   capabilityID OBJECT IDENTIFIER,
	 *   parameters ANY DEFINED BY capabilityID OPTIONAL }
	 * SMIMECapabilities ::= SEQUENCE OF SMIMECapability
	 * </pre>
	 * 
	 * @see <a href="http://www.ietf.org/rfc/rfc2633">RFC 2633</a>
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If and I/O problem occurs
	 */
	private String getSmimeCapabilitiesStringValue(byte[] bValue)
	    throws IOException
	{
		SMIMECapabilities caps = SMIMECapabilities.getInstance(ASN1Object.fromByteArray(bValue));

		String sParams = m_res.getString("SmimeParameters");

		StringBuilder sb = new StringBuilder();

		for (Object o : caps.getCapabilities(null))
		{
			SMIMECapability cap = (SMIMECapability) o;

			String sCapId = cap.getCapabilityID().getId();
			String sCap = getRes(sCapId, "UnrecognisedSmimeCapability");
			sb.append(MessageFormat.format(sCap, sCapId));

			DEREncodable params;
			if ((params = cap.getParameters()) != null)
			{
				sb.append("\n\t");
				sb.append(MessageFormat.format(sParams, stringify(params)));
			}

			sb.append('\n');
		}

		return sb.toString();
	}

	/**
	 * Get Authority Information Access (1.3.6.1.5.5.7.1.1) or Subject Information Access (1.3.6.1.5.5.7.1.11)
	 * extension value as a string.
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getInformationAccessStringValue(byte[] bValue)
	    throws IOException
	{
		AuthorityInformationAccess access =
		    AuthorityInformationAccess.getInstance(ASN1Object.fromByteArray(bValue));

		StringBuilder sb = new StringBuilder();
		String aia = m_res.getString("InformationAccess");

		AccessDescription[] accDescs = access.getAccessDescriptions();
		for (AccessDescription accDesc : accDescs)
		{
			String accOid = accDesc.getAccessMethod().toString();
			String accMeth = getRes(accOid, "UnrecognisedAccessMethod");
			sb.append(MessageFormat.format(aia, MessageFormat.format(accMeth, accOid),
			    getGeneralNameString(accDesc.getAccessLocation())));
			sb.append('\n');
		}

		return sb.toString();
	}

	/**
	 * Get Logotype (1.3.6.1.5.5.7.1.12) extension value as a string.
	 * 
	 * @see <a href="http://www.ietf.org/rfc/rfc3709">RFC 3709</a>
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getLogotypeStringValue(byte[] bValue)
	    throws IOException
	{
		return getUnknownOidStringValue(bValue);

		/*
		 * work-in-progress: ASN1Sequence logos = (ASN1Sequence) ASN1Object.fromByteArray(bValue);
		 * StringBuilder sb = new StringBuilder(); for (int i = 0, len = logos.size(); i < len; i++) {
		 * DERTaggedObject derTag = (DERTaggedObject) logos.getObjectAt(i); switch (derTag.getTagNo()) { case
		 * 0: sb.append(m_res.getString("CommunityLogos")); break; case 1:
		 * sb.append(m_res.getString("IssuerLogo")); DERTaggedObject ltInfo = (DERTaggedObject)
		 * derTag.getObject(); switch (ltInfo.getTagNo()) { case 0: // LogotypeData sb.append("\n\tData");
		 * ASN1Sequence ltData = (ASN1Sequence) ltInfo.getObject(); if (ltData.size() > 0) { ASN1Sequence
		 * ltImage = (ASN1Sequence) ltData.getObjectAt(0); sb.append("\n\t\tImage"); ASN1Sequence ltDetails =
		 * (ASN1Sequence) ltImage.getObjectAt(0); sb.append("\n\t\t\tDetails"); sb.append("\n\t\t\t\tMedia
		 * type: ") .append(((DERString) ltDetails.getObjectAt(0)).getString()); ASN1Sequence ltHash =
		 * (ASN1Sequence) ltDetails.getObjectAt(1); for (int j = 0, jlen = ltHash.size(); j < jlen; j++) {
		 * sb.append("\n\t\t\t\tHash: "); ASN1Sequence haav = (ASN1Sequence) ltHash.getObjectAt(j);
		 * sb.append("<TODO>: "); // haav[0]: alg identifier byte[] bHashValue = ((DEROctetString)
		 * haav.getObjectAt(1)) .getOctets(); sb.append(convertToHexString(bHashValue)); } ASN1Sequence ltURI =
		 * (ASN1Sequence) ltDetails.getObjectAt(2); for (int j = 0, jlen = ltURI.size(); j < jlen; j++) {
		 * sb.append("\n\t\t\t\tURI: ") .append(((DERString) ltURI.getObjectAt(j)).getString()); } if
		 * (ltImage.size() > 1) { ASN1Sequence ltImageInfo = (ASN1Sequence) ltImage.getObjectAt(1);
		 * sb.append("\n\t\t\tImage info"); } if (ltData.size() > 1) { ASN1Sequence ltAudio = (ASN1Sequence)
		 * ltData.getObjectAt(1); sb.append("\n\t\tAudio"); } } break; case 1: // LogotypeReference
		 * sb.append("\n Reference"); break; default: // Unknown, skip } break; case 2:
		 * sb.append(m_res.getString("SubjectLogo")); break; case 3: sb.append(m_res.getString("OtherLogos"));
		 * break; default: // Unknown, skip } } return sb.toString();
		 */
	}

	/**
	 * Get Novell Security Attributes (2.16.840.1.113719.1.9.4.1) extension value as a string.
	 * 
	 * @see <a href="http://developer.novell.com/repository/attributes/">Novell Certificate Extension
	 *      Attributes</a>
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getNovellSecurityAttributesStringValue(byte[] bValue)
	    throws IOException
	{
		// TODO...

		ASN1Sequence attrs = (ASN1Sequence) ASN1Object.fromByteArray(bValue);
		StringBuilder sb = new StringBuilder();

		// "Novell Security Attribute(tm)"
		String sTM = ((DERString) attrs.getObjectAt(2)).getString();
		sb.append(sTM);
		sb.append('\n');

		// OCTET STRING of size 2, 1st is major version, 2nd is minor version
		byte[] bVer = ((DEROctetString) attrs.getObjectAt(0)).getOctets();
		sb.append("Major version: ").append(Byte.toString(bVer[0]));
		sb.append(", minor version: ").append(Byte.toString(bVer[1]));
		sb.append('\n');

		// Nonverified Subscriber Information
		boolean bNSI = ((DERBoolean) attrs.getObjectAt(1)).isTrue();
		sb.append("Nonverified Subscriber Information: ").append(bNSI);
		sb.append('\n');

		// URI reference
		String sUri = ((DERString) attrs.getObjectAt(3)).getString();
		sb.append("URI: ").append(sUri);
		sb.append('\n');

		// GLB Extensions (GLB ~ "Greatest Lower Bound")
		ASN1Sequence glbs = (ASN1Sequence) attrs.getObjectAt(4);
		sb.append("GLB extensions:");
		sb.append('\n');

		/*
		 * TODO: verify that we can do getObjectAt(n) or if we need to examine tag numbers of the tagged
		 * objects
		 */

		// Key quality
		ASN1Sequence keyq = (ASN1Sequence) ((ASN1TaggedObject) glbs.getObjectAt(0)).getObject();
		sb.append('\t').append(m_res.getString("NovellKeyQuality"));
		sb.append('\n').append(getNovellQualityAttr(keyq));

		// Crypto process quality
		ASN1Sequence cpq = (ASN1Sequence) ((ASN1TaggedObject) glbs.getObjectAt(1)).getObject();
		sb.append('\t').append(m_res.getString("NovellCryptoProcessQuality"));
		sb.append('\n').append(getNovellQualityAttr(cpq));

		// Certificate class
		ASN1Sequence cclass = (ASN1Sequence) ((ASN1TaggedObject) glbs.getObjectAt(2)).getObject();
		sb.append('\t');
		sb.append(m_res.getString("NovellCertClass"));
		sb.append('\n');

		sb.append("\t\t");
		BigInteger sv = ((DERInteger) cclass.getObjectAt(0)).getValue();
		String sc = getRes("NovellCertClass." + sv, "UnregocnisedNovellCertClass");
		sb.append(MessageFormat.format(sc, sv));
		sb.append('\n');

		boolean valid = true;
		if (cclass.size() > 1)
		{
			valid = ((DERBoolean) cclass.getObjectAt(1)).isTrue();
		}
		sb.append("\t\t");
		sb.append(m_res.getString("NovellCertClassValid." + valid));
		sb.append('\n');

		// Enterprise ID
		/*
		 * ASN1Sequence eid = (ASN1Sequence) ((ASN1TaggedObject) glbs.getObjectAt(3)).getObject();
		 * ASN1Sequence rootLabel = (ASN1Sequence) ((ASN1TaggedObject) eid.getObjectAt(0)).getObject();
		 * ASN1Sequence registryLabel = (ASN1Sequence) ((ASN1TaggedObject) eid.getObjectAt(1)).getObject();
		 * ASN1Sequence eLabels = (ASN1Sequence) ((ASN1TaggedObject) eid.getObjectAt(2)).getObject(); for (int
		 * i = 0, len = eLabels.size(); i < len; i++) { // Hmm... I thought this would be a sequence of
		 * sequences, // but the following throws a ClassCastException...? // ASN1Sequence eLabel =
		 * (ASN1Sequence) eLabels.getObjectAt(i); }
		 */
		sb.append('\t');
		sb.append(m_res.getString("NovellEnterpriseID"));
		sb.append(' ').append(m_res.getString("DecodeNotImplemented")); // TODO
		sb.append('\n');

		return sb.toString();
	}

	/**
	 * Gets a Novell quality attribute in a decoded, human readable form.
	 * 
	 * @param seq the quality attribute
	 * @return the decoded quality attribute
	 */
	private CharSequence getNovellQualityAttr(ASN1Sequence seq)
	{
		StringBuilder res = new StringBuilder();

		boolean enforceQuality = ((DERBoolean) seq.getObjectAt(0)).isTrue();
		res.append("\t\t").append(m_res.getString("NovellQualityEnforce"));
		res.append(' ').append(enforceQuality).append('\n');

		ASN1Sequence compusecQ = (ASN1Sequence) seq.getObjectAt(1);
		int clen = compusecQ.size();
		if (clen > 0)
		{
			res.append("\t\t");
			res.append(m_res.getString("NovellCompusecQuality"));
			res.append('\n');
		}
		for (int i = 0; i < clen; i++)
		{
			ASN1Sequence cqPair = (ASN1Sequence) compusecQ.getObjectAt(i);

			DERInteger tmp = (DERInteger) cqPair.getObjectAt(0);
			long type = tmp.getValue().longValue();
			String csecCriteria =
			    getRes("NovellCompusecQuality." + type, "UnrecognisedNovellCompusecQuality");
			csecCriteria = MessageFormat.format(csecCriteria, tmp.getValue());
			res.append("\t\t\t").append(csecCriteria);

			tmp = (DERInteger) cqPair.getObjectAt(1);
			String csecRating;
			if (type == 1L)
			{ // TCSEC
				csecRating = getRes("TCSECRating." + tmp.getValue(), "UnrecognisedTCSECRating");
			}
			else
			{
				csecRating = m_res.getString("UnrecognisedNovellQualityRating");
			}
			csecRating = MessageFormat.format(csecRating, tmp.getValue());
			res.append("\n\t\t\t\t").append(m_res.getString("NovellQualityRating"));
			res.append(' ').append(csecRating).append('\n');
		}

		// ASN1Sequence cryptoQ = (ASN1Sequence) seq.getObjectAt(2);
		res.append("\t\t").append(m_res.getString("NovellCryptoQuality"));
		res.append(' ').append(m_res.getString("DecodeNotImplemented")); // TODO
		res.append('\n');
		/*
		 * TODO for (int i = 0, len = cryptoQ.size(); i < len; i++) { ASN1Sequence cqPair = (ASN1Sequence)
		 * cryptoQ.getObjectAt(i); DERInteger cryptoModuleCriteria = (DERInteger) cqPair.getObjectAt(0);
		 * DERInteger cryptoModuleRating = (DERInteger) cqPair.getObjectAt(1); }
		 */

		BigInteger ksqv = ((DERInteger) seq.getObjectAt(3)).getValue();
		String ksq = getRes("NovellKeyStorageQuality." + ksqv, "UnrecognisedNovellKeyStorageQuality");
		res.append("\t\t").append(m_res.getString("NovellKeyStorageQuality"));
		res.append("\n\t\t\t").append(MessageFormat.format(ksq, ksqv));
		res.append('\n');

		return res;
	}

	/** Netscape certificate types */
	private static final int[] NETSCAPE_CERT_TYPES =
	    new int[] { NetscapeCertType.sslClient, NetscapeCertType.sslServer, NetscapeCertType.smime,
	        NetscapeCertType.objectSigning, NetscapeCertType.reserved, NetscapeCertType.sslCA,
	        NetscapeCertType.smimeCA, NetscapeCertType.objectSigningCA, };

	/**
	 * Get Netscape Certificate Type (2.16.840.1.113730.1.1) extension value as a string.
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getNetscapeCertificateTypeStringValue(byte[] bValue)
	    throws IOException
	{
		int val = new NetscapeCertType((DERBitString) ASN1Object.fromByteArray(bValue)).intValue();
		StringBuilder strBuff = new StringBuilder();
		for (int type : NETSCAPE_CERT_TYPES)
		{
			if ((val & type) == type)
			{
				strBuff.append(m_res.getString("NetscapeCertificateType." + type));
				strBuff.append('\n');
			}
		}
		return strBuff.toString();
	}

	/**
	 * Get extension value for any Netscape certificate extension that is <em>not</em> Certificate Type as a
	 * string. (2.16.840.1.113730.1.x, where x can be any of 2, 3, 4, 7, 8, 12 or 13.)
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getNonNetscapeCertificateTypeStringValue(byte[] bValue)
	    throws IOException
	{
		return ((DERIA5String) ASN1Object.fromByteArray(bValue)).getString() + '\n';
	}

	/**
	 * Get extension value for D&amp;B D-U-N-S number as a string.
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getDnBDUNSNumberStringValue(byte[] bValue)
	    throws IOException
	{
		return ((DERIA5String) ASN1Object.fromByteArray(bValue)).getString() + '\n';
	}

	/**
	 * Get extension value for CRL Distribution Points as a string.
	 * 
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getCrlDistributionPointsStringValue(byte[] bValue)
	    throws IOException
	{

		CRLDistPoint dps = CRLDistPoint.getInstance(ASN1Object.fromByteArray(bValue));
		DistributionPoint[] points = dps.getDistributionPoints();

		StringBuilder sb = new StringBuilder();

		for (DistributionPoint point : points)
		{
			DistributionPointName dpn;
			if ((dpn = point.getDistributionPoint()) != null)
			{
				switch (dpn.getType())
				{
					case DistributionPointName.FULL_NAME:
						sb.append(m_res.getString("CrlDistributionPoint.0.0"));
						sb.append('\n');
						sb.append(getGeneralNamesString((GeneralNames) dpn.getName(), "\t"));
						break;
					case DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER:
						sb.append(m_res.getString("CrlDistributionPoint.0.1"));
						// TODO
						sb.append('\t');
						sb.append(dpn.getName());
						sb.append('\n');
						break;
					default:
						// TODO: unknown...
						break;
				}
			}

			ReasonFlags flags;
			if ((flags = point.getReasons()) != null)
			{
				sb.append(m_res.getString("CrlDistributionPoint.1"));
				// TODO
				sb.append('\t');
				sb.append(flags);
				sb.append('\n');
			}

			GeneralNames issuer;
			if ((issuer = point.getCRLIssuer()) != null)
			{
				sb.append(m_res.getString("CrlDistributionPoint.2"));
				sb.append('\n');
				sb.append(getGeneralNamesString(issuer, "\t"));
			}
		}

		return sb.toString();
	}

	/**
	 * Get extension value for Certificate Policies as a string.
	 * 
	 * @see <a href="http://www.ietf.org/rfc/rfc3280">RFC 3280</a>
	 * @param bValue The octet string value
	 * @return Extension value as a string
	 * @throws IOException If an I/O problem occurs
	 */
	private String getCertificatePoliciesStringValue(byte[] bValue)
	    throws IOException
	{
		ASN1Sequence pSeq = (ASN1Sequence) ASN1Object.fromByteArray(bValue);
		StringBuilder sb = new StringBuilder();

		for (int i = 0, len = pSeq.size(); i < len; i++)
		{

			PolicyInformation pi = PolicyInformation.getInstance(pSeq.getObjectAt(i));

			// TODO: 2.5.29.32.0 (any policy?)

			sb.append(MessageFormat.format(m_res.getString("PolicyIdentifier"),
			    pi.getPolicyIdentifier().getId()));
			sb.append('\n');

			ASN1Sequence pQuals;
			if ((pQuals = pi.getPolicyQualifiers()) != null)
			{
				for (int j = 0, plen = pQuals.size(); j < plen; j++)
				{

					ASN1Sequence pqi = (ASN1Sequence) pQuals.getObjectAt(j);
					String pqId = ((DERObjectIdentifier) pqi.getObjectAt(0)).getId();

					sb.append('\t');
					sb.append(MessageFormat.format(getRes(pqId, "UnrecognisedPolicyQualifier"), pqId));
					sb.append('\n');

					if (pQuals.size() > 0)
					{

						DEREncodable d = pqi.getObjectAt(1);

						if (pqId.equals("1.3.6.1.5.5.7.2.1"))
						{
							// cPSuri
							sb.append("\t\t");
							sb.append(MessageFormat.format(m_res.getString("CpsUri"),
							    ((DERString) d).getString()));
							sb.append('\n');
						}
						else if (pqId.equals("1.3.6.1.5.5.7.2.2"))
						{
							// userNotice
							ASN1Sequence un = (ASN1Sequence) d;

							for (int k = 0, dlen = un.size(); k < dlen; k++)
							{
								DEREncodable de = un.getObjectAt(k);

								// TODO: is it possible to use something
								// smarter than instanceof here?

								if (de instanceof DERString)
								{
									// explicitText
									sb.append("\t\t");
									sb.append(m_res.getString("ExplicitText"));
									sb.append("\n\t\t\t");
									sb.append(stringify(de));
									sb.append('\n');
								}
								else if (de instanceof ASN1Sequence)
								{
									// noticeRef
									ASN1Sequence nr = (ASN1Sequence) de;
									String orgstr = stringify(nr.getObjectAt(0));
									ASN1Sequence nrs = (ASN1Sequence) nr.getObjectAt(1);
									StringBuilder nrstr = new StringBuilder();
									for (int m = 0, nlen = nrs.size(); m < nlen; m++)
									{
										nrstr.append(stringify(nrs.getObjectAt(m)));
										if (m != nlen - 1)
										{
											nrstr.append(", ");
										}
									}
									sb.append("\t\t");
									sb.append(m_res.getString("NoticeRef"));
									sb.append("\n\t\t\t");
									sb.append(MessageFormat.format(m_res.getString("NoticeRefOrganization"),
									    orgstr));
									sb.append("\n\t\t\t");
									sb.append(MessageFormat.format(m_res.getString("NoticeRefNumber"), nrstr));
									sb.append('\n');
								}
								else
								{
									// TODO
								}
							}
						}
						else
						{
							sb.append("\t\t");
							sb.append(stringify(d));
							sb.append('\n');
						}
					}
				}
			}

			if (i != len)
			{
				sb.append('\n');
			}
		}

		return sb.toString();
	}

	/**
	 * Get the supplied general name as a string ([general name type]=[general name]).
	 * 
	 * <pre>
	 * GeneralName ::= CHOICE {
	 *     otherName                       [0]     OtherName,
	 *     rfc822Name                      [1]     IA5String, x
	 *     dNSName                         [2]     IA5String, x
	 *     x400Address                     [3]     ORAddress,
	 *     directoryName                   [4]     Name, x
	 *     ediPartyName                    [5]     EDIPartyName,
	 *     uniformResourceIdentifier       [6]     IA5String, x
	 *     iPAddress                       [7]     OCTET STRING, x
	 *     registeredID                    [8]     OBJECT IDENTIFIER x }
	 * OtherName ::= SEQUENCE {
	 *     type-id    OBJECT IDENTIFIER,
	 *     value      [0] EXPLICIT ANY DEFINED BY type-id }
	 * EDIPartyName ::= SEQUENCE {
	 *     nameAssigner            [0]     DirectoryString OPTIONAL,
	 *     partyName               [1]     DirectoryString }
	 * DirectoryString ::= CHOICE {
	 *     teletexString           TeletexString (SIZE (1..maxSize),
	 *     printableString         PrintableString (SIZE (1..maxSize)),
	 *     universalString         UniversalString (SIZE (1..maxSize)),
	 *     utf8String              UTF8String (SIZE (1.. MAX)),
	 *     bmpString               BMPString (SIZE(1..maxSIZE)) }
	 * </pre>
	 * 
	 * @param generalName The general name
	 * @return General name string
	 */
	private String getGeneralNameString(GeneralName generalName)
	{
		StringBuilder strBuff = new StringBuilder();

		switch (generalName.getTagNo())
		{

			case GeneralName.otherName:
				ASN1Sequence other = (ASN1Sequence) generalName.getName();
				String sOid = ((DERObjectIdentifier) other.getObjectAt(0)).getId();
				String sVal = stringify(other.getObjectAt(1));
				try
				{
					String tmp = m_res.getString(sOid);
					strBuff.append(MessageFormat.format(tmp, sVal));
				}
				catch (MissingResourceException e)
				{
					String tmp = m_res.getString("OtherGeneralName");
					strBuff.append(MessageFormat.format(tmp, sOid, sVal));
				}
				break;

			case GeneralName.rfc822Name:
				String sRfc822 = ((DERIA5String) generalName.getName()).getString();
				strBuff.append(MessageFormat.format(m_res.getString("Rfc822GeneralName"), sRfc822));
				break;

			case GeneralName.dNSName:
				String sDns = ((DERIA5String) generalName.getName()).getString();
				strBuff.append(MessageFormat.format(m_res.getString("DnsGeneralName"), sDns));
				break;

			case GeneralName.directoryName:
				ASN1Sequence directory = (ASN1Sequence) generalName.getName();
				X509Name name = new X509Name(directory);
				strBuff.append(MessageFormat.format(m_res.getString("DirectoryGeneralName"), name.toString()));
				break;

			case GeneralName.uniformResourceIdentifier:
				String sUri = ((DERIA5String) generalName.getName()).getString();
				strBuff.append(MessageFormat.format(m_res.getString("UriGeneralName"), sUri));
				break;

			case GeneralName.iPAddress:
				ASN1OctetString ipAddress = (ASN1OctetString) generalName.getName();

				byte[] bIpAddress = ipAddress.getOctets();

				// Output the IP Address components one at a time separated by dots
				StringBuilder sbIpAddress = new StringBuilder();

				for (int iCnt = 0, bl = bIpAddress.length; iCnt < bl; iCnt++)
				{
					// Convert from (possibly negative) byte to positive int
					sbIpAddress.append(bIpAddress[iCnt] & 0xFF);
					if ((iCnt + 1) < bIpAddress.length)
					{
						sbIpAddress.append('.');
					}
				}

				strBuff.append(MessageFormat.format(m_res.getString("IpAddressGeneralName"),
				    sbIpAddress.toString()));
				break;

			case GeneralName.registeredID:
				strBuff.append(MessageFormat.format(m_res.getString("RegisteredIdGeneralName"),
				    generalName.getName().toString()));
				break;

			case GeneralName.x400Address: // TODO
			case GeneralName.ediPartyName: // TODO
			default: // Unsupported general name type
				strBuff.append(MessageFormat.format(m_res.getString("UnsupportedGeneralNameType"),
				    generalName.getTagNo()));
				break;
		}

		return strBuff.toString();
	}

	/**
	 * Get a formatted string value for the supplied general names object.
	 * 
	 * @param generalNames General names
	 * @return Formatted string
	 */
	private String getGeneralNamesString(GeneralNames generalNames, String indent)
	{
		GeneralName[] names = generalNames.getNames();
		StringBuilder strBuff = new StringBuilder();
		for (GeneralName name : names)
		{
			strBuff.append(indent);
			strBuff.append(getGeneralNameString(name));
			strBuff.append('\n');
		}
		return strBuff.toString();
	}

	/**
	 * Get a formatted string value for the supplied generalized time object.
	 * 
	 * @param time Generalized time
	 * @return Formatted string
	 * @throws ParseException If there is a problem formatting the generalized time
	 */
	private String formatGeneralizedTime(DERGeneralizedTime time)
	    throws ParseException
	{
		// Get generalized time as a string
		String sTime = time.getTime();

		// Setup date formatter with expected date format of string
		DateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmssz");

		// Create date object from string using formatter
		Date date = dateFormat.parse(sTime);

		// Re-format date - include timezone
		sTime = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.LONG).format(date);

		return sTime;
	}

	/**
	 * Get hex and clear text dump of byte array.
	 * 
	 * @param bytes Array of bytes
	 * @param iLen Bytes in array
	 * @return Hex dump
	 */
	private String getHexClearDump(byte[] bytes, int iLen)
	{
		// Buffer for hex
		StringBuilder sbHex = new StringBuilder();

		// Buffer for clear text
		StringBuilder sbClr = new StringBuilder();

		// Populate buffers for hex and clear text

		// For each byte...
		for (int iCnt = 0; iCnt < iLen; iCnt++)
		{
			// Convert byte to int
			int i = bytes[iCnt] & 0xFF;

			// First part of byte will be one hex char
			int i1 = (int) Math.floor((double) i / 16);

			// Second part of byte will be one hex char
			int i2 = i % 16;

			// Get hex characters
			sbHex.append(Character.toUpperCase(Character.forDigit(i1, 16)));
			sbHex.append(Character.toUpperCase(Character.forDigit(i2, 16)));

			if ((iCnt + 1) < iLen)
			{
				// Divider between hex characters
				sbHex.append(' ');
			}

			// Get clear character

			// Character to display if character not define din Unicode or
			// is a control character
			char c = '.';

			// Not a control character and defined in Unicode
			if (!Character.isISOControl((char) i) && Character.isDefined((char) i))
			{
				Character cClr = new Character((char) i);
				c = cClr.charValue();
			}

			sbClr.append(c);
		}

		/*
		 * Put both dumps together in one string (hex, clear) with approriate padding between them (pad to
		 * array length)
		 */
		StringBuilder strBuff = new StringBuilder(sbHex.length() + sbClr.length() + 4);

		strBuff.append(sbHex);

		int iMissing = bytes.length - iLen;
		for (int iCnt = 0; iCnt < iMissing; iCnt++)
		{
			strBuff.append("   ");
		}

		strBuff.append("   ");
		strBuff.append(sbClr);
		strBuff.append('\n');

		return strBuff.toString();
	}

	/**
	 * Convert the supplied object to a hex string sub-divided by spaces every four characters.
	 * 
	 * @param obj Object (byte array, BigInteger, DERInteger)
	 * @return Hex string
	 */
	private static String convertToHexString(Object obj)
	{
		BigInteger bigInt;
		if (obj instanceof BigInteger)
		{
			bigInt = (BigInteger) obj;
		}
		else if (obj instanceof byte[])
		{
			bigInt = new BigInteger(1, (byte[]) obj);
		}
		else if (obj instanceof DERInteger)
		{
			bigInt = ((DERInteger) obj).getValue();
		}
		else
		{
			throw new IllegalArgumentException("Don't know how to convert " + obj.getClass().getName() +
			    " to a hex string");
		}

		// Convert to hex
		StringBuilder strBuff = new StringBuilder(bigInt.toString(16).toUpperCase());

		// Place spaces at every four hex characters
		if (strBuff.length() > 4)
		{
			for (int iCnt = 4; iCnt < strBuff.length(); iCnt += 5)
			{
				strBuff.insert(iCnt, ' ');
			}
		}

		return strBuff.toString();
	}

	/**
	 * Gets a string representation of the given object.
	 * 
	 * @param obj Object
	 * @return String representation <code>obj</code>
	 */
	private static String stringify(Object obj)
	{
		if (obj instanceof DERString)
		{
			return ((DERString) obj).getString();
		}
		else if (obj instanceof DERInteger || obj instanceof byte[])
		{
			return convertToHexString(obj);
		}
		else if (obj instanceof ASN1TaggedObject)
		{
			ASN1TaggedObject tagObj = (ASN1TaggedObject) obj;
			// Note: "[", _not_ '[' ...
			return "[" + tagObj.getTagNo() + "] " + stringify(tagObj.getObject());
		}
		else if (obj instanceof ASN1Sequence)
		{
			ASN1Sequence aObj = (ASN1Sequence) obj;
			StringBuilder tmp = new StringBuilder("[");
			for (int i = 0, len = aObj.size(); i < len; i++)
			{
				tmp.append(stringify(aObj.getObjectAt(i)));
				if (i != len - 1)
				{
					tmp.append(", ");
				}
			}
			return tmp.append("]").toString();
		}
		else
		{
			String hex = null;
			try
			{
				Method method = obj.getClass().getMethod("getOctets", (Class[]) null);
				hex = convertToHexString(method.invoke(obj, (Object[]) null));
			}
			catch (Exception e)
			{
				// Ignore
			}
			if (hex == null && obj != null)
			{
				hex = obj.toString();
			}
			return hex;
		}
	}

	/**
	 * Gets a resource string, with fallback.
	 * 
	 * @param key the key
	 * @param fallback the fallback key
	 * @return a resource string
	 */
	private static String getRes(String key, String fallback)
	{
		try
		{
			return m_res.getString(key);
		}
		catch (MissingResourceException e)
		{
			return m_res.getString(fallback);
		}
	}

}
