/*
 * X509Ext.java
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
import java.io.IOException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.text.DateFormat;
import java.text.MessageFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.bouncycastle.asn1.ASN1InputStream;
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
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.smime.SMIMECapabilities;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.X509Name;

/**
 * Holds the information of an X.509 extension and provides the ability
 * to get the extension's name and value as a string.
 */
public class X509Ext
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/crypto/resources");

    /////////////////////////////////////////////
    // Extension OIDs
    /////////////////////////////////////////////

    /** Common name OID */
    private static final String COMMON_NAME_OID = "2.5.4.3";

    /** Authority Key Identifier (old) OID */
    private static final String AUTHORITY_KEY_IDENTIFIER_OLD_OID = "2.5.29.1";

    /** Primary Key Attributes OID */  // No info available
    private static final String PRIMARY_KEY_ATTRIBUTES_OID = "2.5.29.2";

    /** Certificate Policies (old) OID */
    private static final String CERTIFICATE_POLICIES_OLD_OID = "2.5.29.3";

    /** Primary Key Usage Restriction (old) OID */  // Old - not to do?
    private static final String PRIMARY_KEY_USAGE_RESTRICTION_OID = "2.5.29.4";

    /** Subject Directory Attributes OID */ // Std todo
    private static final String SUBJECT_DIRECTORY_ATTRIBUTES_OID = "2.5.29.9";

    /** Basic Constraints (old 0) OID */
    private static final String BASIC_CONSTRAINTS_OLD_0_OID = "2.5.29.10";

    /** Basic Constraints (old 1) OID */ // Old - not to do?
    private static final String BASIC_CONSTRAINTS_OLD_1_OID = "2.5.29.13";

    /** Subject Key Identifier OID */
    private static final String SUBJECT_KEY_IDENTIFIER_OID = "2.5.29.14";

    /** Key Usage OID */
    private static final String KEY_USAGE_OID = "2.5.29.15";

    /** Private Key Usage Period OID */
    private static final String PRIVATE_KEY_USAGE_PERIOD_OID = "2.5.29.16";

    /** Subject Alternative Name OID */
    private static final String SUBJECT_ALTERNATIVE_NAME_OID = "2.5.29.17";

    /** Issuer Alternative Name OID */
    private static final String ISSUER_ALTERNATIVE_NAME_OID = "2.5.29.18";

    /** Basic Constraints OID */
    private static final String BASIC_CONSTRAINTS_OID = "2.5.29.19";

    /** CRL Number OID */
    private static final String CRL_NUMBER_OID = "2.5.29.20";

    /** Reason code OID */
    private static final String REASON_CODE_OID = "2.5.29.21";

    /** Hold Instruction Code OID */
    private static final String HOLD_INSTRUCTION_CODE_OID = "2.5.29.23";

    /** Invalidity Date OID */
    private static final String INVALIDITY_DATE_OID = "2.5.29.24";

    /** CRL Distribution Points (old) OID */ // Old - not to do?
    private static final String CRL_DISTRIBUTION_POINTS_OLD_OID = "2.5.29.25";

    /** Delta CRL Indicator OID */
    private static final String DELTA_CRL_INDICATOR_OID = "2.5.29.27";

    /** Issuing Distribution Point OID */ // Std todo
    private static final String ISSUING_DISTRIBUTION_POINT_OID = "2.5.29.28";

    /** Certificate Issuer OID */
    private static final String CERTIFICATE_ISSUER_OID = "2.5.29.29";

    /** Name Constraints OID */ // Std todo
    private static final String NAME_CONSTRAINTS_OID = "2.5.29.30";

    /** CRL Distribution Points OID */
    private static final String CRL_DISTRIBUTION_POINTS_OID = "2.5.29.31";

    /** Certificate Policies OID */ // Std todo
    private static final String CERTIFICATE_POLICIES_OID = "2.5.29.32";

    /** Policy Mappings OID */
    private static final String POLICY_MAPPINGS_OID = "2.5.29.33";

    /** Policy Constraints (old) OID */ // Old - not to do?
    private static final String POLICY_CONSTRAINTS_OLD_OID = "2.5.29.34";

    /** Authority Key Identifier OID */
    private static final String AUTHORITY_KEY_IDENTIFIER_OID = "2.5.29.35";

    /** Policy Constraints OID */
    private static final String POLICY_CONSTRAINTS_OID = "2.5.29.36";

    /** Extended Key Usage OID */
    private static final String EXTENDED_KEY_USAGE_OID = "2.5.29.37";

    /** CRL Stream Identifier OID */ // No info available
    private static final String CRL_STREAM_IDENTIFIER_OID = "2.5.29.40";

    /** CRL Scope OID */ // No info available
    private static final String CRL_SCOPE_OID = "2.5.29.44";

    /** Status Referrals OID */ // No info available
    private static final String STATUS_REFERRALS_OID = "2.5.29.45";

    /** Freshest CRL OID */ // Std todo
    private static final String FRESHEST_CRL_OID = "2.5.29.46";

    /** Ordered List OID */ // No info available
    private static final String ORDERED_LIST_OID = "2.5.29.47";

    /** Base Update Time OID */ // No info available
    private static final String BASE_UPDATE_TIME_OID = "2.5.29.51";

    /** Delta Information OID */ // No info available
    private static final String DELTA_INFORMATION_OID = "2.5.29.53";

    /** Inhibit Any Policy OID */
    private static final String INHIBIT_ANY_POLICY_OID = "2.5.29.54";

    /** Entrust version extension OID */
    private static final String ENTRUST_VERSION_EXTENSION_OID =
        "1.2.840.113533.7.65.0";

    /** S/MIME capabilities OID */
    private static final String SMIME_CAPABILITIES_OID =
        "1.2.840.113549.1.9.15";

    /** Microsoft certificate template name OID */
    private static final String MICROSOFT_CERTIFICATE_TEMPLATE_V1_OID =
        "1.3.6.1.4.1.311.20.2";

    /** Microsoft CA version OID */
    private static final String MICROSOFT_CA_VERSION_OID =
        "1.3.6.1.4.1.311.21.1";

    /** Microsoft certificate template (v2) OID */
    private static final String MICROSOFT_CERTIFICATE_TEMPLATE_V2_OID =
        "1.3.6.1.4.1.311.21.7";

    /** Microsoft application policies OID */
    private static final String MICROSOFT_APPLICATION_POLICIES_OID =
        "1.3.6.1.4.1.311.21.10";

    /** Authority Information Access OID */
    private static final String AUTHORITY_INFORMATION_ACCESS_OID =
        "1.3.6.1.5.5.7.1.1";

    /** Novell Security Attributes OID */
    private static final String NOVELL_SECURITY_ATTRIBUTES_OID =
        "2.16.840.1.113719.1.9.4.1";

    /** Netscape Certificate Type OID */
    private static final String NETSCAPE_CERTIFICATE_TYPE_OID =
        "2.16.840.1.113730.1.1";

    /** Netscape Base URL OID */
    private static final String NETSCAPE_BASE_URL_OID =
        "2.16.840.1.113730.1.2";

    /** Netscape Revocation URL OID */
    private static final String NETSCAPE_REVOCATION_URL_OID =
        "2.16.840.1.113730.1.3";

    /** Netscape CA Revocation URL OID */
    private static final String NETSCAPE_CA_REVOCATION_URL_OID =
        "2.16.840.1.113730.1.4";

    /** Netscape Certificate Renewal URL OID */
    private static final String NETSCAPE_CERTIFICATE_RENEWAL_URL_OID =
        "2.16.840.1.113730.1.7";

    /** Netscape CA Policy URL OID */
    private static final String NETSCAPE_CA_POLICY_URL_OID =
        "2.16.840.1.113730.1.8";

    /** Netscape SSL Server Name OID */
    private static final String NETSCAPE_SSL_SERVER_NAME_OID =
        "2.16.840.1.113730.1.12";

    /** Netscape Comment OID */
    private static final String NETSCAPE_COMMENT_OID =
        "2.16.840.1.113730.1.13";

    /** D&B D-U-N-S number OID */
    private static final String DNB_DUNS_NUMBER_OID =
        "2.16.840.1.113733.1.6.15";


    /** Extension name or OID if unknown */
    private final String m_sName;

    /** Extension object identifier */
    private final String m_sOid;

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
        m_sOid = sOid;

        m_bValue = new byte[bValue.length];
        System.arraycopy(bValue, 0, m_bValue, 0, bValue.length);

        m_bCritical = bCritical;

        m_sName = getRes(m_sOid, "UnrecognisedExtension");
    }

    /**
     * Get extension object identifier.
     *
     * @return Extension object identifier
     */
    public String getOid()
    {
        return m_sOid;
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
    public String getStringValue() throws IOException, ParseException
    {
        // Get octet string from extension
        byte[] bOctets = ((DEROctetString) toDER(m_bValue)).getOctets();

        // Octet string processed differently depending on extension type
        if (m_sOid.equals(COMMON_NAME_OID))
        {
            return getCommonNameStringValue(bOctets);
        }
        else if (m_sOid.equals(SUBJECT_KEY_IDENTIFIER_OID))
        {
            return getSubjectKeyIndentifierStringValue(bOctets);
        }
        else if (m_sOid.equals(KEY_USAGE_OID))
        {
            return getKeyUsageStringValue(bOctets);
        }
        else if (m_sOid.equals(PRIVATE_KEY_USAGE_PERIOD_OID))
        {
            return getPrivateKeyUsagePeriod(bOctets);
        }
        else if (m_sOid.equals(SUBJECT_ALTERNATIVE_NAME_OID))
        {
            return getSubjectAlternativeName(bOctets);
        }
        else if (m_sOid.equals(ISSUER_ALTERNATIVE_NAME_OID))
        {
            return getIssuerAlternativeName(bOctets);
        }
        else if (m_sOid.equals(BASIC_CONSTRAINTS_OID))
        {
            return getBasicConstraintsStringValue(bOctets);
        }
        else if (m_sOid.equals(CRL_NUMBER_OID))
        {
            return getCrlNumberStringValue(bOctets);
        }
        else if (m_sOid.equals(REASON_CODE_OID))
        {
            return getReasonCodeStringValue(bOctets);
        }
        else if (m_sOid.equals(HOLD_INSTRUCTION_CODE_OID))
        {
            return getHoldInstructionCodeStringValue(bOctets);
        }
        else if (m_sOid.equals(INVALIDITY_DATE_OID))
        {
            return getInvalidityDateStringValue(bOctets);
        }
        else if (m_sOid.equals(DELTA_CRL_INDICATOR_OID))
        {
            return getDeltaCrlIndicatorStringValue(bOctets);
        }
        else if (m_sOid.equals(CERTIFICATE_ISSUER_OID))
        {
            return getCertificateIssuerStringValue(bOctets);
        }
        else if (m_sOid.equals(POLICY_MAPPINGS_OID))
        {
            return getPolicyMappingsStringValue(bOctets);
        }
        else if (m_sOid.equals(AUTHORITY_KEY_IDENTIFIER_OID))
        {
            return getAuthorityKeyIdentifierStringValue(bOctets);
        }
        else if (m_sOid.equals(POLICY_CONSTRAINTS_OID))
        {
            return getPolicyConstraintsStringValue(bOctets);
        }
        else if (m_sOid.equals(EXTENDED_KEY_USAGE_OID))
        {
            return getExtendedKeyUsageStringValue(bOctets);
        }
        else if (m_sOid.equals(INHIBIT_ANY_POLICY_OID))
        {
            return getInhibitAnyPolicyStringValue(bOctets);
        }
        else if (m_sOid.equals(ENTRUST_VERSION_EXTENSION_OID))
        {
            return getEntrustVersionExtensionStringValue(bOctets);
        }
        else if (m_sOid.equals(SMIME_CAPABILITIES_OID))
        {
            return getSmimeCapabilitiesStringValue(bOctets);
        }
        else if (m_sOid.equals(MICROSOFT_CERTIFICATE_TEMPLATE_V1_OID))
        {
            return getMicrosoftCertificateTemplateV1StringValue(bOctets);
        }
        else if (m_sOid.equals(MICROSOFT_CA_VERSION_OID))
        {
            return getMicrosoftCAVersionStringValue(bOctets);
        }
        else if (m_sOid.equals(MICROSOFT_CERTIFICATE_TEMPLATE_V2_OID))
        {
            return getMicrosoftCertificateTemplateV2StringValue(bOctets);
        }
        else if (m_sOid.equals(MICROSOFT_APPLICATION_POLICIES_OID))
        {
            return getUnknownOidStringValue(bOctets); // TODO
        }
        else if (m_sOid.equals(AUTHORITY_INFORMATION_ACCESS_OID))
        {
            return getAuthorityInformationAccessStringValue(bOctets);
        }
        else if (m_sOid.equals(NOVELL_SECURITY_ATTRIBUTES_OID))
        {
            return getNovellSecurityAttributesStringValue(bOctets);
        }
        else if (m_sOid.equals(NETSCAPE_CERTIFICATE_TYPE_OID))
        {
            return getNetscapeCertificateTypeStringValue(bOctets);
        }
        else if (m_sOid.equals(NETSCAPE_BASE_URL_OID) ||
                 m_sOid.equals(NETSCAPE_REVOCATION_URL_OID) ||
                 m_sOid.equals(NETSCAPE_CA_REVOCATION_URL_OID) ||
                 m_sOid.equals(NETSCAPE_CERTIFICATE_RENEWAL_URL_OID) ||
                 m_sOid.equals(NETSCAPE_CA_POLICY_URL_OID) ||
                 m_sOid.equals(NETSCAPE_SSL_SERVER_NAME_OID) ||
                 m_sOid.equals(NETSCAPE_COMMENT_OID))
        {
            return getNonNetscapeCertificateTypeStringValue(bOctets);
        }
        else if (m_sOid.equals(DNB_DUNS_NUMBER_OID))
        {
            return getDnBDUNSNumberStringValue(bOctets);
        }
        else if (m_sOid.equals(CRL_DISTRIBUTION_POINTS_OID))
        {
            return getCrlDistributionPointsStringValue(bOctets);
        }
        else if (m_sOid.equals(CERTIFICATE_POLICIES_OID))
        {
            return getCertificatePoliciesStringValue(bOctets);
        }

        // TODO:
        // - CERTIFICATE_POLICIES_OLD_OID
        // - AUTHORITY_KEY_IDENTIFIER_OLD_OID
        // - BASIC_CONSTRAINTS_OLD_0_OID

        // Don't know how to process the extension
        // and clear text
        else {
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
    private String getUnknownOidStringValue(byte[] bValue) throws IOException
    {
        ByteArrayInputStream bais = null;
        int nBytes = 16; // how many bytes to show per line

        try {
            // Divide dump into 16 byte lines
            StringBuffer strBuff = new StringBuffer();

            bais = new ByteArrayInputStream(bValue);
            byte[] bLine = new byte[nBytes];
            int iRead = -1;

            while ((iRead = bais.read(bLine)) != -1)
            {
                strBuff.append(getHexClearDump(bLine, iRead));
            }

            return strBuff.toString();
        }
        finally {
            try { if (bais != null)  bais.close(); }
            catch (IOException ex) { /* Ignore */ }
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
        return stringify(toDER(bValue));
    }


    /**
     * Get Subject Key Indentifier (2.5.29.14) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getSubjectKeyIndentifierStringValue(byte[] bValue)
        throws IOException
    {
        /* SubjectKeyIdentifier ::= KeyIdentifier

           KeyIdentifier ::= OCTET STRING */

        DEROctetString derOctetStr = (DEROctetString) toDER(bValue);

        byte[] bKeyIdent = derOctetStr.getOctets();

        // Output as a hex string
        StringBuffer strBuff = new StringBuffer();
        strBuff.append(convertToHexString(bKeyIdent));
        strBuff.append('\n');
        return strBuff.toString();
    }

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
    private String getKeyUsageStringValue(byte[] bValue) throws IOException
    {
        DERBitString derBitStr = (DERBitString) toDER(bValue);
        StringBuffer strBuff = new StringBuffer();

        byte[] bytes = derBitStr.getBytes();

        boolean bKeyAgreement = false;

        // Loop through bit string appending them to the returned string
        // value as flags are found true
        for (int iCnt=0; iCnt < bytes.length; iCnt++)
        {
            boolean[] b = new boolean[8];

            b[7] = (bytes[iCnt] & 0x80) == 0x80;
            b[6] = (bytes[iCnt] & 0x40) == 0x40;
            b[5] = (bytes[iCnt] & 0x20) == 0x20;
            b[4] = (bytes[iCnt] & 0x10) == 0x10;
            b[3] = (bytes[iCnt] & 0x8) == 0x8;
            b[2] = (bytes[iCnt] & 0x4) == 0x4;
            b[1] = (bytes[iCnt] & 0x2) == 0x2;
            b[0] = (bytes[iCnt] & 0x1) == 0x1;

            // First byte
            if (iCnt == 0) {
                if (b[7]) {
                    strBuff.append(
                        m_res.getString("DigitalSignatureKeyUsageString"));
                    strBuff.append('\n');
                }
                if (b[6]) {
                    strBuff.append(
                        m_res.getString("NonRepudiationKeyUsageString"));
                    strBuff.append('\n');
                }
                if (b[5]) {
                    strBuff.append(
                        m_res.getString("KeyEnciphermentKeyUsageString"));
                    strBuff.append('\n');
                }
                if (b[4]) {
                    strBuff.append(
                        m_res.getString("DataEnciphermentKeyUsageString"));
                    strBuff.append('\n');
                }
                if (b[3]) {
                    strBuff.append(
                        m_res.getString("KeyAgreementKeyUsageString"));
                    strBuff.append('\n');
                    bKeyAgreement = true;
                }
                if (b[2]) {
                    strBuff.append(
                        m_res.getString("KeyCertSignKeyUsageString"));
                    strBuff.append('\n');
                }
                if (b[1]) {
                    strBuff.append(m_res.getString("CrlSignKeyUsageString"));
                    strBuff.append('\n');
                }
                // Only has meaning if key agreement set
                if (b[0] && bKeyAgreement) {
                    strBuff.append(
                        m_res.getString("EncipherOnlyKeyUsageString"));
                    strBuff.append('\n');
                }
            }
            // Second byte
            else if (iCnt == 1) {
                // Only has meaning if key agreement set
                if (b[7] && bKeyAgreement) {
                    strBuff.append(
                        m_res.getString("DecipherOnlyKeyUsageString"));
                    strBuff.append('\n');
                }
            }
        }

        return strBuff.toString();
    }


    /**
     * Get Private Key Usage Period (2.5.29.16) extension value as a string.
     * <pre>
     * PrivateKeyUsagePeriod ::= SEQUENCE {
     *       notBefore       [0]     GeneralizedTime OPTIONAL,
     *       notAfter        [1]     GeneralizedTime OPTIONAL }
     * </pre>
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     * @throws ParseException If a date formatting problem occurs
     */
    private String getPrivateKeyUsagePeriod(byte[] bValue)
        throws IOException, ParseException
    {
        ASN1Sequence times = (ASN1Sequence) toDER(bValue);

        StringBuffer strBuff = new StringBuffer();

        for (int i = 0, len = times.size(); i < len; i++)
        {
            DERTaggedObject derTag = (DERTaggedObject) times.getObjectAt(i);
            DEROctetString dOct = (DEROctetString) derTag.getObject();
            DERGeneralizedTime dTime =
                new DERGeneralizedTime(new String(dOct.getOctets()));

            strBuff.append(
                MessageFormat.format(
                    m_res.getString("PrivateKeyUsagePeriod." +
                                    derTag.getTagNo()),
                    new String[]{formatGeneralizedTime(dTime)}));
            strBuff.append('\n');
        }

        return strBuff.toString();
    }


    /**
     * Get Subject Alternative Name (2.5.29.17) extension value as a string.
     *
     * <pre>
     * SubjectAltName ::= GeneralNames
     *
     * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
     * </pre>
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getSubjectAlternativeName(byte[] bValue) throws IOException
    {
        ASN1Sequence generalNames = (ASN1Sequence) toDER(bValue);
        StringBuffer strBuff = new StringBuffer();
        for (int i = 0, len = generalNames.size(); i < len; i++) {
            strBuff.append(getGeneralNameString(
                               (DERTaggedObject) generalNames.getObjectAt(i)));
            strBuff.append('\n');
        }
        return strBuff.toString();
    }


    /**
     * Get Issuer Alternative Name (2.5.29.18) extension value as a string.
     *
     * <pre>
     * SubjectAltName ::= GeneralNames
     *
     * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
     * </pre>
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getIssuerAlternativeName(byte[] bValue) throws IOException
    {
        ASN1Sequence generalNames = (ASN1Sequence) toDER(bValue);
        StringBuffer strBuff = new StringBuffer();
        for (int i = 0, len = generalNames.size(); i < len; i++)
        {
            strBuff.append(getGeneralNameString(
                               (DERTaggedObject) generalNames.getObjectAt(i)));
            strBuff.append('\n');
        }
        return strBuff.toString();
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
        // Get sequence
        ASN1Sequence asn1Seq = (ASN1Sequence) toDER(bValue);
        int aLen = asn1Seq.size();

        // Default values when none specified in sequence
        boolean bCa = false;
        int iPathLengthConstraint = -1;

        // Read CA boolean if present in sequence
        if (aLen > 0) {
            DERBoolean derBool = (DERBoolean)asn1Seq.getObjectAt(0);
            bCa = derBool.isTrue();
        }

        // Read Path Length Constraint boolean if present in sequence
        if (aLen > 1) {
            DERInteger derInt = (DERInteger)asn1Seq.getObjectAt(1);
            iPathLengthConstraint = derInt.getValue().intValue();
        }

        // Output information
        StringBuffer strBuff = new StringBuffer();

        // Subject is CA?
        strBuff.append(m_res.getString(bCa ? "SubjectIsCa" :"SubjectIsNotCa"));
        strBuff.append('\n');

        // Path length constraint (only has meaning when CA is true)
        if (iPathLengthConstraint != -1 && bCa) {
            strBuff.append(MessageFormat.format(
                               m_res.getString("PathLengthConstraint"),
                               new String[]{""+iPathLengthConstraint}));
        }
        else {
            strBuff.append(m_res.getString("NoPathLengthConstraint"));
        }
        strBuff.append('\n');

        return strBuff.toString();
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
    private String getCrlNumberStringValue(byte[] bValue) throws IOException
    {
        // Get CRL number
        DERInteger derInt = (DERInteger) toDER(bValue);

        // Convert to and return hex string representation of number
        StringBuffer strBuff = new StringBuffer();
        strBuff.append(convertToHexString(derInt));
        strBuff.append('\n');
        return strBuff.toString();
    }


    /**
     * Get Reason Code (2.5.29.21) extension value as a string.
     *
     * <pre>
     * ReasonCode ::= { CRLReason }
     *
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
    private String getReasonCodeStringValue(byte[] bValue) throws IOException
    {
        int iRc = ((DEREnumerated) toDER(bValue)).getValue().intValue();
        String sRc = getRes("CrlReason."+iRc, "UnrecognisedCrlReasonString");
        return MessageFormat.format(sRc, new String[]{""+iRc}) + '\n';
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
        String sHoldIns = ((DERObjectIdentifier) toDER(bValue)).getId();
        String res = getRes(sHoldIns, "UnrecognisedHoldInstructionCode");
        return MessageFormat.format(res, new String[]{sHoldIns}) + '\n';
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
        DERGeneralizedTime invalidityDate = (DERGeneralizedTime) toDER(bValue);

        // Format invalidity date for display
        String sInvalidityTime = formatGeneralizedTime(invalidityDate);

        StringBuffer strBuff = new StringBuffer();
        strBuff.append(sInvalidityTime);
        strBuff.append('\n');
        return strBuff.toString();
    }


    /**
     * Get Delta CRL Indicator (2.5.29.27) extension value as a string.
     *
     * <pre>
     * BaseCRLNumber ::= CRLNumber
     *
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
        DERInteger derInt = (DERInteger) toDER(bValue);

        // Convert to and return hex string representation of number
        StringBuffer strBuff = new StringBuffer();
        strBuff.append(convertToHexString(derInt));
        strBuff.append('\n');
        return strBuff.toString();
    }


    /**
     * Get Certificate Issuer (2.5.29.29) extension value as a string.
     *
     * <pre>
     * certificateIssuer ::= GeneralNames
     *
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
        ASN1Sequence generalNames = (ASN1Sequence) toDER(bValue);
        StringBuffer strBuff = new StringBuffer();
        for (int i = 0, len = generalNames.size(); i < len; i++)
        {
            strBuff.append(getGeneralNameString(
                               (DERTaggedObject) generalNames.getObjectAt(i)));
            strBuff.append('\n');
        }
        return strBuff.toString();
    }


    /**
     * Get Policy Mappings (2.5.29.33) extension value as a string.
     *
     * <pre>
     * PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
     *     issuerDomainPolicy      CertPolicyId,
     *      subjectDomainPolicy     CertPolicyId }
     *
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
        ASN1Sequence policyMappings = (ASN1Sequence) toDER(bValue);

        StringBuffer strBuff = new StringBuffer();

        // Get each policy mapping
        for (int i = 0, len = policyMappings.size(); i < len; i++)
        {
            ASN1Sequence policyMapping =
                (ASN1Sequence) policyMappings.getObjectAt(i);
            int pmLen = policyMapping.size();

            strBuff.append(MessageFormat.format(
                               m_res.getString("PolicyMapping"),
                               new String[]{""+(i+1)}));
            strBuff.append('\n');

            if (pmLen > 0) { // Policy mapping issuer domain policy
                DERObjectIdentifier issuerDomainPolicy =
                    (DERObjectIdentifier) policyMapping.getObjectAt(0);
                strBuff.append('\t');
                strBuff.append(MessageFormat.format(
                                   m_res.getString("IssuerDomainPolicy"),
                                   new String[]{issuerDomainPolicy.getId()}));
                strBuff.append('\n');
            }

            if (pmLen > 1) { // Policy mapping subject domain policy
                DERObjectIdentifier subjectDomainPolicy =
                    (DERObjectIdentifier) policyMapping.getObjectAt(1);
                strBuff.append('\t');
                strBuff.append(MessageFormat.format(
                                   m_res.getString("SubjectDomainPolicy"),
                                   new String[]{subjectDomainPolicy.getId()}));
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
     *
     * KeyIdentifier ::= OCTET STRING
     *
     * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
     *
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
        /* Get sequence of (all optional) a key identifier, an authority
           cert issuer names and an authority cert serial number */
        ASN1Sequence asn1Seq = (ASN1Sequence) toDER(bValue);

        DEROctetString keyIdentifier = null;
        ASN1Sequence authorityCertIssuer = null;
        DEROctetString certificateSerialNumber = null;

        for (int i = 0, len = asn1Seq.size(); i < len; i++)
        {
            DERTaggedObject derTagObj =
                (DERTaggedObject) asn1Seq.getObjectAt(i);
            DERObject derObj = (DERObject)derTagObj.getObject();

            switch (derTagObj.getTagNo()) {
            case 0: // Key identifier
                keyIdentifier = (DEROctetString)derObj;
                break;
            case 1: // Authority cert issuer
                // Many general names
                if (derObj instanceof ASN1Sequence) {
                    authorityCertIssuer = (ASN1Sequence)derObj;
                }
                // One general name
                else {
                    authorityCertIssuer = new DERSequence(derObj);
                }
                break;
            case 2: // Certificate serial number
                certificateSerialNumber = (DEROctetString)derObj;
                break;
            }
        }

        StringBuffer strBuff = new StringBuffer();

        if (keyIdentifier != null) {
            byte[] bKeyIdent = keyIdentifier.getOctets();
            strBuff.append(MessageFormat.format(
                               m_res.getString("KeyIdentifier"),
                               new String[]{convertToHexString(bKeyIdent)}));
            strBuff.append('\n');
        }

        if (authorityCertIssuer != null) {
            strBuff.append(m_res.getString("CertificateIssuer"));
            strBuff.append('\n');
            for (int i = 0, len = authorityCertIssuer.size(); i < len; i++) {
                DERTaggedObject generalName =
                    (DERTaggedObject) authorityCertIssuer.getObjectAt(i);
                strBuff.append('\t');
                strBuff.append(getGeneralNameString(generalName));
                strBuff.append('\n');
            }
        }

        if (certificateSerialNumber != null) {
            byte[] bCertSerialNumber = certificateSerialNumber.getOctets();
            strBuff.append(MessageFormat.format(
                               m_res.getString("CertificateSerialNumber"),
                               new String[]{convertToHexString(
                                                bCertSerialNumber)}));
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
     *
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
        ASN1Sequence policyConstraints = (ASN1Sequence) toDER(bValue);

        StringBuffer strBuff = new StringBuffer();

        for (int i = 0, len = policyConstraints.size(); i < len; i++) {

            DERTaggedObject policyConstraint =
                (DERTaggedObject) policyConstraints.getObjectAt(i);
            DERInteger skipCerts = new DERInteger(
                ((DEROctetString)policyConstraint.getObject()).getOctets());
            int iSkipCerts = skipCerts.getValue().intValue();

            switch (policyConstraint.getTagNo()) {
            case 0: // Require Explicit Policy Skip Certs
                strBuff.append(MessageFormat.format(
                                   m_res.getString("RequireExplicitPolicy"),
                                   new String[]{""+iSkipCerts}));
                strBuff.append('\n');
                break;
            case 1: // Inhibit Policy Mapping Skip Certs
                strBuff.append(MessageFormat.format(
                                   m_res.getString("InhibitPolicyMapping"),
                                   new String[]{""+iSkipCerts}));
                strBuff.append('\n');
                break;
            }
        }

        return strBuff.toString();

    }


    /**
     * Get Extended Key Usage (2.5.29.37) extension value as a string.
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
        ASN1Sequence asn1Seq = (ASN1Sequence) toDER(bValue);

        StringBuffer strBuff = new StringBuffer();

        for (int i = 0, len = asn1Seq.size(); i < len; i++)
        {
            String sOid =
                ((DERObjectIdentifier) asn1Seq.getObjectAt(i)).getId();
            String sEku = getRes(sOid, "UnrecognisedExtKeyUsageString");
            strBuff.append(MessageFormat.format(sEku, new String[]{sOid}));
            strBuff.append('\n');
        }

        return strBuff.toString();
    }


    /**
     * Get Inhibit Any Policy (2.5.29.54) extension value as a string.
     *
     * <pre>
     * InhibitAnyPolicy ::= SkipCerts
     *
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
        DERInteger skipCerts = (DERInteger) toDER(bValue);

        int iSkipCerts = skipCerts.getValue().intValue();

        // Return inhibit any policy extension
        StringBuffer strBuff = new StringBuffer();
        strBuff.append(MessageFormat.format(
                           m_res.getString("InhibitAnyPolicy"),
                           new String[]{""+iSkipCerts}));
        strBuff.append('\n');
        return strBuff.toString();
    }


    /**
     * Get Entrust Version Extension (1.2.840.113533.7.65.0) extension
     * value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getEntrustVersionExtensionStringValue(byte[] bValue)
        throws IOException
    {
        // SEQUENCE encapsulated in a OCTET STRING
        ASN1Sequence as = (ASN1Sequence) toDER(bValue);
        // Also has BIT STRING, ignored here
        // http://www.mail-archive.com/openssl-dev@openssl.org/msg06546.html
        return ((DERGeneralString) as.getObjectAt(0)).getString();
    }


    /**
     * Get Microsoft certificate template name V1 (1.3.6.1.4.1.311.20.2)
     * extension value as a string.
     *
     * @see <a href="http://support.microsoft.com/?kbid=291010">Microsoft KB article 291010</a>
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If and I/O problem occurs
     */
    private String getMicrosoftCertificateTemplateV1StringValue(byte[] bValue)
        throws IOException
    {
        return ((DERBMPString) toDER(bValue)).getString() + '\n';
    }


    /**
     * Get Microsoft certificate template name V2 (1.3.6.1.4.1.311.20.7)
     * extension value as a string.
     * <pre>
     * CertificateTemplate ::= SEQUENCE {
     *   templateID OBJECT IDENTIFIER,
     *   templateMajorVersion TemplateVersion,
     *   templateMinorVersion TemplateVersion OPTIONAL
     * }
     * TemplateVersion ::= INTEGER (0..4294967295)
     * </pre>
     *
     * @see <a href="http://groups.google.com/groups?selm=OXFILYELDHA.1908%40TK2MSFTNGP11.phx.gbl">http://groups.google.com/groups?selm=OXFILYELDHA.1908%40TK2MSFTNGP11.phx.gbl</a>
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If and I/O problem occurs
     */
    private String getMicrosoftCertificateTemplateV2StringValue(byte[] bValue)
        throws IOException
    {
        ASN1Sequence seq = (ASN1Sequence) toDER(bValue);
        StringBuffer sb = new StringBuffer();

        sb.append(MessageFormat.format(
                      m_res.getString("MsftCertTemplateId"),
                      new String[]{
                          ((DERObjectIdentifier)seq.getObjectAt(0)).getId()}));
        sb.append('\n');

        DERInteger derInt = (DERInteger) seq.getObjectAt(1);
        sb.append(MessageFormat.format(
                      m_res.getString("MsftCertTemplateMajorVer"),
                      new String[]{derInt.getValue().toString()}));
        sb.append('\n');

        if ((derInt = (DERInteger) seq.getObjectAt(2)) != null) {
            sb.append(MessageFormat.format(
                          m_res.getString("MsftCertTemplateMinorVer"),
                          new String[]{derInt.getValue().toString()}));
            sb.append('\n');
        }

        return sb.toString();
    }


    /**
     * Get Microsoft CA Version (1.3.6.1.4.1.311.21.1) extension value as
     * a string.
     *
     * @see <a href="http://msdn.microsoft.com/library/en-us/security/security/certification_authority_renewal.asp">MSDN</a>
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If and I/O problem occurs
     */
    private String getMicrosoftCAVersionStringValue(byte[] bValue)
        throws IOException
    {
        int ver = ((DERInteger) toDER(bValue)).getValue().intValue();
        String certIx = String.valueOf(ver & 0xffff); // low 16 bits
        String keyIx = String.valueOf(ver >> 16);     // high 16 bits
        return MessageFormat.format(
            m_res.getString("MsftCaVersion"),new String[]{certIx, keyIx})+'\n';
    }


    /**
     * Get S/MIME capabilities (1.2.840.113549.1.9.15) extension value as
     * a string.
     *
     * <pre>
     * SMIMECapability ::= SEQUENCE {
     *   capabilityID OBJECT IDENTIFIER,
     *   parameters ANY DEFINED BY capabilityID OPTIONAL }
     *
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
        SMIMECapabilities caps = SMIMECapabilities.getInstance(toDER(bValue));

        String sParams = m_res.getString("SmimeParameters");

        StringBuffer sb = new StringBuffer();

        for (Iterator i = caps.getCapabilities(null).iterator(); i.hasNext(); )
        {
            SMIMECapability cap = (SMIMECapability) i.next();

            String sCapId = cap.getCapabilityID().getId();
            String sCap = getRes(sCapId, "UnrecognisedSmimeCapability");
            sb.append(MessageFormat.format(sCap, new String[]{sCapId}));

            DEREncodable params;
            if ((params = cap.getParameters()) != null) {
                sb.append("\n\t");
                sb.append(MessageFormat.format(
                              sParams, new String[]{stringify(params)}));
            }

            sb.append('\n');
        }

        return sb.toString();
    }


    /**
     * Get Authority Information Access (1.3.6.1.5.5.7.1.1) extension
     * value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getAuthorityInformationAccessStringValue(byte[] bValue)
        throws IOException
    {
        ASN1Sequence accDescs = (ASN1Sequence) toDER(bValue);

        StringBuffer sb = new StringBuffer();
        String aia = m_res.getString("AuthorityInformationAccess");

        for (int i = 0, adLen = accDescs.size(); i < adLen; i++) {
            ASN1Sequence accDesc = (ASN1Sequence) accDescs.getObjectAt(i);
            String accOid =
                ((DERObjectIdentifier) accDesc.getObjectAt(0)).getId();
            String accMeth = getRes(accOid, "UnrecognisedAccessMethod");
            String accLoc = getGeneralNameString(
                (DERTaggedObject) accDesc.getObjectAt(1));
            sb.append(
                MessageFormat.format(
                    aia, new String[]{
                        MessageFormat.format(accMeth, new String[]{accOid}),
                        accLoc}));
            sb.append('\n');
        }

        return sb.toString();
    }


    /**
     * Get Novell Security Attributes (2.16.840.1.113719.1.9.4.1) extension
     * value as a string.
     *
     * @see <a href="http://developer.novell.com/repository/attributes/">Novell
 Certificate Extension Attributes</a>
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getNovellSecurityAttributesStringValue(byte[] bValue)
        throws IOException
    {
        // TODO...

        ASN1Sequence attrs = (ASN1Sequence) toDER(bValue);
        StringBuffer sb = new StringBuffer();

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

        /* TODO:
         * verify that we can do getObjectAt(n) or if we need to examine
         * tag numbers of the tagged objects
         */

        // Key quality
        ASN1Sequence keyq = (ASN1Sequence)
            ((ASN1TaggedObject) glbs.getObjectAt(0)).getObject();
        boolean enforceQuality = ((DERBoolean) keyq.getObjectAt(0)).isTrue();
        ASN1Sequence compusecQ = (ASN1Sequence) keyq.getObjectAt(1);
        for (int i = 0, len = compusecQ.size(); i < len; i++) {
            ASN1Sequence cqPair = (ASN1Sequence) compusecQ.getObjectAt(i);
            DERInteger csecCriteria = (DERInteger) cqPair.getObjectAt(0);
            DERInteger csecRating = (DERInteger) cqPair.getObjectAt(1);
        }
        ASN1Sequence cryptoQ = (ASN1Sequence) keyq.getObjectAt(2);
        for (int i = 0, len = cryptoQ.size(); i < len; i++) {
            ASN1Sequence cqPair = (ASN1Sequence) cryptoQ.getObjectAt(i);
            DERInteger cryptoModuleCriteria =
                (DERInteger) cqPair.getObjectAt(0);
            DERInteger cryptoModuleRating =
                (DERInteger) cqPair.getObjectAt(1);
        }

        String ksqv = ((DERInteger) keyq.getObjectAt(3)).getValue().toString();
        String ksq = getRes("NovellKeyStorageQuality." + ksqv,
                            "UnrecognisedNovellKeyStorageQuality");

        sb.append('\t').append(m_res.getString("NovellKeyQuality"));
        sb.append("\n\t\t").append(m_res.getString("NovellKeyQualityEnforce"));
        sb.append(' ').append(enforceQuality).append('\n');

        sb.append("\t\t").append(m_res.getString("NovellCompusecQuality"));
        sb.append(' ').append(m_res.getString("DecodeNotImplemented")); // TODO
        sb.append('\n');

        sb.append("\t\t").append(m_res.getString("NovellCryptoQuality"));
        sb.append(' ').append(m_res.getString("DecodeNotImplemented")); // TODO
        sb.append('\n');

        sb.append("\t\t").append(m_res.getString("NovellKeyStorageQuality"));
        sb.append("\n\t\t\t").append(
            MessageFormat.format(ksq, new String[]{ksqv}));
        sb.append('\n');

        // Crypto process quality
        ASN1Sequence cpq = (ASN1Sequence)
            ((ASN1TaggedObject) glbs.getObjectAt(1)).getObject();
        sb.append('\t');
        sb.append(m_res.getString("NovellCryptoProcessQuality"));
        sb.append(' ').append(m_res.getString("DecodeNotImplemented")); // TODO
        // TODO: reuse from key quality
        sb.append('\n');

        // Certificate class
        ASN1Sequence cclass = (ASN1Sequence)
            ((ASN1TaggedObject) glbs.getObjectAt(2)).getObject();
        sb.append('\t');
        sb.append(m_res.getString("NovellCertClass"));
        sb.append('\n');

        sb.append("\t\t");
        String sv = ((DERInteger) cclass.getObjectAt(0)).getValue().toString();
        String sc = getRes("NovellCertClass." + sv,
                           "UnregocnisedNovellCertClass");
        sb.append(MessageFormat.format(sc, new String[]{sv}));
        sb.append('\n');

        boolean valid = true;
        if (cclass.size() > 1) {
            valid = ((DERBoolean) cclass.getObjectAt(1)).isTrue();
        }
        sb.append("\t\t");
        sb.append(m_res.getString("NovellCertClassValid." + valid));
        sb.append('\n');

        // Enterprise ID
        ASN1Sequence eid = (ASN1Sequence)
            ((ASN1TaggedObject) glbs.getObjectAt(3)).getObject();
        ASN1Sequence rootLabel = (ASN1Sequence)
            ((ASN1TaggedObject) eid.getObjectAt(0)).getObject();
        ASN1Sequence registryLabel = (ASN1Sequence)
            ((ASN1TaggedObject) eid.getObjectAt(1)).getObject();
        ASN1Sequence eLabels = (ASN1Sequence)
            ((ASN1TaggedObject) eid.getObjectAt(2)).getObject();
        for (int i = 0, len = eLabels.size(); i < len; i++) {
            // Hmm... I thought this would be a sequence of sequences,
            // but the following throws a ClassCastException...?
            // ASN1Sequence eLabel = (ASN1Sequence) eLabels.getObjectAt(i);
        }
        sb.append('\t');
        sb.append(m_res.getString("NovellEnterpriseID"));
        sb.append(' ').append(m_res.getString("DecodeNotImplemented")); // TODO
        sb.append('\n');

        return sb.toString();
    }


    /**
     * Get Netscape Certificate Type (2.16.840.1.113730.1.1) extension value
     * as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getNetscapeCertificateTypeStringValue(byte[] bValue)
        throws IOException
    {
       // Get bits
        byte[] bytes = ((DERBitString) toDER(bValue)).getBytes();

        StringBuffer strBuff = new StringBuffer();
        boolean bKeyAgreement = false;

        if (bytes.length != 0)
        {
            boolean[] b = new boolean[8];

            b[7] = (bytes[0] & 0x80) == 0x80;
            b[6] = (bytes[0] & 0x40) == 0x40;
            b[5] = (bytes[0] & 0x20) == 0x20;
            b[4] = (bytes[0] & 0x10) == 0x10;
            b[3] = (bytes[0] & 0x8) == 0x8;
            b[2] = (bytes[0] & 0x4) == 0x4;
            b[1] = (bytes[0] & 0x2) == 0x2;
            b[0] = (bytes[0] & 0x1) == 0x1;

            if (b[7])
            {
                strBuff.append(
                    m_res.getString("SslClientNetscapeCertificateType"));
                strBuff.append('\n');
            }

            if (b[6])
            {
                strBuff.append(
                    m_res.getString("SslServerNetscapeCertificateType"));
                strBuff.append('\n');
            }

            if (b[5])
            {
                strBuff.append(
                    m_res.getString("SmimeNetscapeCertificateType"));
                strBuff.append('\n');
            }

            if (b[4])
            {
                strBuff.append(
                    m_res.getString("ObjectSigningNetscapeCertificateType"));
                strBuff.append('\n');
                bKeyAgreement = true;
            }

            if (b[2])
            {
                strBuff.append(
                    m_res.getString("SslCaNetscapeCertificateType"));
                strBuff.append('\n');
            }

            if (b[1])
            {
                strBuff.append(
                    m_res.getString("SmimeCaNetscapeCertificateType"));
                strBuff.append('\n');
            }

            if (b[0])
            {
                strBuff.append(
                    m_res.getString("ObjectSigningCaNetscapeCertificateType"));
                strBuff.append('\n');
            }
        }

        return strBuff.toString();
    }


    /**
     * Get extension value for any Netscape certificate extension that is
     * <em>not</em> Certificate Type as a string. (2.16.840.1.113730.1.x,
     * where x can be any of 2, 3, 4, 7, 8, 12 or 13.)
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getNonNetscapeCertificateTypeStringValue(byte[] bValue)
        throws IOException
    {
        return ((DERIA5String) toDER(bValue)).getString() + '\n';
    }


    /**
     * Get extension value for D&B D-U-N-S number as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getDnBDUNSNumberStringValue(byte[] bValue)
        throws IOException
    {
        return ((DERIA5String) toDER(bValue)).getString() + '\n';
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

        CRLDistPoint dps = CRLDistPoint.getInstance(toDER(bValue));
        DistributionPoint[] points = dps.getDistributionPoints();

        StringBuffer sb = new StringBuffer();

        for (int i = 0, len = points.length; i < len; i++)
        {
            DistributionPoint point = points[i];

            DistributionPointName dpn;
            if ((dpn = point.getDistributionPoint()) != null) {
                ASN1TaggedObject tagObj =
                    (ASN1TaggedObject) dpn.toASN1Object();
                switch (tagObj.getTagNo()) {
                case DistributionPointName.FULL_NAME:
                    sb.append(m_res.getString("CrlDistributionPoint.0.0"));
                    sb.append('\n');
                    ASN1Sequence seq = (ASN1Sequence) tagObj.getObject();
                    for (int j = 0, nLen = seq.size(); j < nLen; j++)
                    {
                        sb.append('\t');
                        sb.append(getGeneralNameString(
                                      (DERTaggedObject) seq.getObjectAt(j)));
                        sb.append('\n');
                    }
                    break;
                case DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER:
                    sb.append(m_res.getString("CrlDistributionPoint.0.1"));
                    // TODO
                    sb.append('\t');
                    sb.append(tagObj.getObject());
                    sb.append('\n');
                    break;
                default:
                    // TODO: unknown...
                    break;
                }
            }

            ReasonFlags flags;
            if ((flags = point.getReasons()) != null) {
                sb.append(m_res.getString("CrlDistributionPoint.1"));
                // TODO
                sb.append('\t');
                sb.append(flags);
                sb.append('\n');
            }

            GeneralNames issuer;
            if ((issuer = point.getCRLIssuer()) != null) {
                sb.append(m_res.getString("CrlDistributionPoint.2"));
                sb.append('\n');
                ASN1Sequence seq = (ASN1Sequence) issuer.getDERObject();
                for (int j = 0, iLen = seq.size(); j < iLen; j++) {
                    sb.append('\t');
                    sb.append(getGeneralNameString(
                                  (DERTaggedObject) seq.getObjectAt(j)));
                    sb.append('\n');
                }
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
        ASN1Sequence pSeq = (ASN1Sequence) toDER(bValue);
        StringBuffer sb = new StringBuffer();

        for (int i = 0, len = pSeq.size(); i < len; i++) {

            PolicyInformation pi =
                PolicyInformation.getInstance(pSeq.getObjectAt(i));

            // TODO: 2.5.29.32.0 (any policy?)

            sb.append(MessageFormat.format(
                          m_res.getString("PolicyIdentifier"),
                          new String[]{pi.getPolicyIdentifier().getId()}));
            sb.append('\n');

            ASN1Sequence pQuals;
            if ((pQuals = (ASN1Sequence) pi.getPolicyQualifiers()) != null) {
                for (int j = 0, plen = pQuals.size(); j < plen; j++) {

                    ASN1Sequence pqi = (ASN1Sequence) pQuals.getObjectAt(j);
                    String pqId =
                        ((DERObjectIdentifier) pqi.getObjectAt(0)).getId();
                    

                    sb.append('\t');
                    sb.append(MessageFormat.format(
                                  getRes(pqId, "UnrecognisedPolicyQualifier"),
                                  new String[]{pqId}));
                    sb.append('\n');

                    if (pQuals.size() > 0) {

                        DEREncodable d = pqi.getObjectAt(1);

                        if (pqId.equals("1.3.6.1.5.5.7.2.1")) {
                            // cPSuri
                            sb.append("\t\t");
                            sb.append(MessageFormat.format(
                                          m_res.getString("CpsUri"),
                                          new String[]{
                                              ((DERString) d).getString()}));
                            sb.append('\n');
                        }
                        else if (pqId.equals("1.3.6.1.5.5.7.2.2")) {
                            // userNotice
                            ASN1Sequence un = (ASN1Sequence) d;

                            for (int k = 0, dlen = un.size(); k < dlen; k++) {
                                DEREncodable de =
                                    (DEREncodable) un.getObjectAt(k);

                                // TODO: is it possible to use something
                                // smarter than instanceof here?

                                if (de instanceof DERString) {
                                    // explicitText
                                    sb.append("\t\t");
                                    sb.append(m_res.getString("ExplicitText"));
                                    sb.append("\n\t\t\t");
                                    sb.append(stringify(de));
                                    sb.append('\n');
                                }
                                else if (de instanceof ASN1Sequence) {
                                    // noticeRef
                                    ASN1Sequence nr = (ASN1Sequence) de;
                                    String orgstr =
                                        stringify(nr.getObjectAt(0));
                                    ASN1Sequence nrs =
                                        (ASN1Sequence) nr.getObjectAt(1);
                                    StringBuffer nrstr = new StringBuffer();
                                    for (int m = 0, nlen = nrs.size();
                                         m < nlen; m++)
                                    {
                                        nrstr.append(
                                            stringify(nrs.getObjectAt(m)));
                                        if (m != nlen - 1) {
                                            nrstr.append(", ");
                                        }
                                    }
                                    sb.append("\t\t");
                                    sb.append(m_res.getString("NoticeRef"));
                                    sb.append("\n\t\t\t");
                                    sb.append(MessageFormat.format(
                                                  m_res.getString(
                                                      "NoticeRefOrganization"),
                                                  new String[]{orgstr}));
                                    sb.append("\n\t\t\t");
                                    sb.append(MessageFormat.format(
                                                  m_res.getString(
                                                      "NoticeRefNumber"),
                                                  new Object[]{nrstr}));
                                    sb.append('\n');
                                }
                                else {
                                    // TODO
                                }
                            }
                        }
                        else {
                            sb.append("\t\t");
                            sb.append(stringify(d));
                            sb.append('\n');
                        }
                    }
                }
            }

            if (i != len) {
                sb.append('\n');
            }
        }

        return sb.toString();
    }


    /**
     * Get the supplied general name as a string
     * ([general name type]=[general name]).
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
     *
     * OtherName ::= SEQUENCE {
     *     type-id    OBJECT IDENTIFIER,
     *     value      [0] EXPLICIT ANY DEFINED BY type-id }
     *
     * EDIPartyName ::= SEQUENCE {
     *     nameAssigner            [0]     DirectoryString OPTIONAL,
     *     partyName               [1]     DirectoryString }
     *
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
    private String getGeneralNameString(DERTaggedObject generalName)
    {
        StringBuffer strBuff = new StringBuffer();

        switch (generalName.getTagNo()) {

        case 0: // Other Name
            ASN1Sequence other = (ASN1Sequence)generalName.getObject();
            String sOid = ((DERObjectIdentifier) other.getObjectAt(0)).getId();
            String sVal = stringify(other.getObjectAt(1));
            strBuff.append(MessageFormat.format(
                               m_res.getString("OtherGeneralName"),
                               new String[]{sOid, sVal}));
            break;

        case 1: // RFC 822 Name
            DEROctetString rfc822 = (DEROctetString)generalName.getObject();
            String sRfc822 = new String(rfc822.getOctets());
            strBuff.append(MessageFormat.format(
                               m_res.getString("Rfc822GeneralName"),
                               new String[]{sRfc822}));
            break;

        case 2: // DNS Name
            DEROctetString dns = (DEROctetString)generalName.getObject();
            String sDns = new String(dns.getOctets());
            strBuff.append(MessageFormat.format(
                               m_res.getString("DnsGeneralName"),
                               new String[]{sDns}));
            break;

        case 4: // Directory Name
            ASN1Sequence directory = (ASN1Sequence)generalName.getObject();
            X509Name name = new X509Name(directory);
            strBuff.append(MessageFormat.format(
                               m_res.getString("DirectoryGeneralName"),
                               new String[]{name.toString()}));
            break;

        case 6: // URI
            DEROctetString uri = (DEROctetString)generalName.getObject();
            String sUri = new String(uri.getOctets());
            strBuff.append(MessageFormat.format(
                               m_res.getString("UriGeneralName"),
                               new String[]{sUri}));
            break;

        case 7: // IP Address
            DEROctetString ipAddress = (DEROctetString)generalName.getObject();

            byte[] bIpAddress = ipAddress.getOctets();

            // Output the IP Address components one at a time separated by dots
            StringBuffer sbIpAddress = new StringBuffer();

            for (int iCnt = 0, bl = bIpAddress.length; iCnt < bl; iCnt++)
            {
                // Convert from (possibly negative) byte to positive int
                sbIpAddress.append((int) bIpAddress[iCnt] & 0xFF);
                if ((iCnt+1) < bIpAddress.length) {
                    sbIpAddress.append('.');
                }
            }

            strBuff.append(MessageFormat.format(
                               m_res.getString("IpAddressGeneralName"),
                               new String[]{sbIpAddress.toString()}));
            break;

        case 8: // Registered ID
            DEROctetString registeredId =
                (DEROctetString)generalName.getObject();

            byte[] bRegisteredId = registeredId.getOctets();

            // Output the components one at a time separated by dots
            StringBuffer sbRegisteredId = new StringBuffer();

            for (int iCnt = 0; iCnt < bRegisteredId.length; iCnt++)
            {
                byte b = bRegisteredId[iCnt];
                // Convert from (possibly negative) byte to positive int
                sbRegisteredId.append((int)b & 0xFF);
                if ((iCnt+1) < bRegisteredId.length) {
                    sbRegisteredId.append('.');
                }
            }

            strBuff.append(MessageFormat.format(
                               m_res.getString("RegisteredIdGeneralName"),
                               new String[]{sbRegisteredId.toString()}));
            break;

        default: // Unsupported general name type
            strBuff.append(MessageFormat.format(
                               m_res.getString("UnsupportedGeneralNameType"),
                               new String[]{""+generalName.getTagNo()}));
            break;
        }

        return strBuff.toString();
    }


    /**
     * Get a formatted string value for the supplied generalized time object.
     *
     * @param time Generalized time
     * @return Formatted string
     * @throws ParseException If there is a problem formatting the
     * generalized time
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
        sTime = DateFormat.getDateTimeInstance(
            DateFormat.MEDIUM, DateFormat.LONG).format((Date)date);

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
        StringBuffer sbHex = new StringBuffer();

        // Buffer for clear text
        StringBuffer sbClr = new StringBuffer();

        // Populate buffers for hex and clear text

        // For each byte...
        for (int iCnt=0; iCnt < iLen; iCnt++)
        {
            // Convert byte to int
            byte b = bytes[iCnt];
            int i = (int) b & 0xFF;

            // First part of byte will be one hex char
            int i1 = (int)Math.floor(i / 16);

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
            if (!Character.isISOControl((char)i) &&
                Character.isDefined((char)i))
            {
                Character cClr = new Character((char)i);
                c = cClr.charValue();
            }

            sbClr.append(c);
        }

        /* Put both dumps together in one string (hex, clear) with
           approriate padding between them (pad to array length) */
        StringBuffer strBuff = new StringBuffer();

        strBuff.append(sbHex.toString());
        sbHex = new StringBuffer();

        int iMissing = bytes.length - iLen;
        for (int iCnt=0; iCnt < iMissing; iCnt++)
        {
            strBuff.append("   ");
        }

        strBuff.append("   ");
        strBuff.append(sbClr.toString());
        sbClr = new StringBuffer();
        strBuff.append('\n');

        return strBuff.toString();
    }


    /**
     * Convert the supplied DER Integer to a hex string sub-divided by spaces
     * every four characters.
     *
     * @param derInt DER Integer
     * @return Hex string
     */
    private static String convertToHexString(DERInteger derInt)
    {
        // Convert number to hex string - divide string with a space
        // every four characters
        String sHexCrlNumber = derInt.getValue().toString(16).toUpperCase();

        StringBuffer strBuff = new StringBuffer();

        for (int iCnt=0; iCnt < sHexCrlNumber.length(); iCnt++)
        {
            strBuff.append(sHexCrlNumber.charAt(iCnt));

            if ((((iCnt+1) % 4) == 0) && ((iCnt+1) != sHexCrlNumber.length()))
            {
                strBuff.append(' ');
            }
        }

        return strBuff.toString();
    }


    /**
     * Convert the supplied byte array to a hex string sub-divided by spaces
     * every four characters.
     *
     * @param bytes Byte array
     * @return Hex string
     */
    private static String convertToHexString(byte[] bytes)
    {
        // Convert to hex
        StringBuffer strBuff = new StringBuffer(
            new BigInteger(1, bytes).toString(16).toUpperCase());

        // Place spaces at every four hex characters
        if (strBuff.length() > 4) {
            for (int iCnt=4; iCnt < strBuff.length(); iCnt+=5)
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
        if (obj instanceof DERString) {
            return ((DERString) obj).getString();
        } else if (obj instanceof DERInteger) {
            return convertToHexString((DERInteger) obj);
        }
        else if (obj instanceof byte[]) {
            return convertToHexString((byte[]) obj);
        }
        else if (obj instanceof ASN1TaggedObject) {
            ASN1TaggedObject tagObj = (ASN1TaggedObject) obj;
            // Note: "[", _not_ '[' ...
            return "[" + tagObj.getTagNo() + "] " +
                stringify(tagObj.getObject());
        }
        else {
            String hex = null;
            try {
                Method method = obj.getClass().getMethod("getOctets", null);
                hex = convertToHexString((byte[]) method.invoke(obj, null));
            }
            catch (Exception e) {
                // Ignore
            }
            if (hex == null && obj != null) {
                hex = obj.toString();
            }
            return hex;
        }
    }


    /**
     * Gets a DER object from the given byte array.
     *
     * @param bytes bytes
     * @return a DER object
     */
    private static DERObject toDER(byte[] bytes)
        throws IOException
    {
        ASN1InputStream in =
            new ASN1InputStream(new ByteArrayInputStream(bytes));
        try {
            return in.readObject();
        }
        finally {
            if (in != null) {
                try { in.close(); } catch (IOException e) { /* Ignore */ }
            }
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
        try {
            return m_res.getString(key);
        }
        catch (MissingResourceException e) {
            return m_res.getString(fallback);
        }
    }

}
