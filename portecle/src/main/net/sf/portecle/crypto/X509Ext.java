/*
 * X509Ext.java
 *
 * Copyright (C) 2004 Wayne Grant
 * waynedgrant@hotmail.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * (This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

package net.sf.portecle.crypto;

import java.io.*;
import java.math.BigInteger;
import java.text.MessageFormat;
import java.util.*;
import java.text.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;

/**
 * Holds the information of an X.509 extension and provides the ability
 * to get the extension's name and value as a string.
 */
public class X509Ext extends Object
{
    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/crypto/resources");

    /** Extension name or OID if unknown */
    private String m_sName;

    /** Extension object identifier */
    private String m_sOid;

    /** Extension value as a DER-encoded OCTET string */
    private byte[] m_bValue;

    /** Critical extension? */
    private boolean m_bCritical;

    /////////////////////////////////////////////
    // Extension OIDs
    /////////////////////////////////////////////

    /** Authority Key Identifier (old) OID */
    private static final String AUTHORITY_KEY_IDENTIFIER_OLD_OID = "2.5.29.1"; // Old - not to do?

    /** Primary Key Attributes OID */
    private static final String PRIMARY_KEY_ATTRIBUTES_OID = "2.5.29.2"; // No info available

    /** Certificate Policies (old) OID */
    private static final String CERTIFICATE_POLICIES_OLD_OID = "2.5.29.3"; // Old - not to do?

    /** Primary Key Usage Restriction OID */
    private static final String PRIMARY_KEY_USAGE_RESTRICTION_OID = "2.5.29.4"; // No info available

    /** Subject Directory Attributes OID */
    private static final String SUBJECT_DIRECTORY_ATTRIBUTES_OID = "2.5.29.9"; // Std todo

    /** Basic Constraints (old 0) OID */
    private static final String BASIC_CONSTRAINTS_OLD_0_OID = "2.5.29.10"; // Old - not to do?

    /** Basic Constraints (old 1) OID */
    private static final String BASIC_CONSTRAINTS_OLD_1_OID = "2.5.29.13"; // Old - not to do?

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

    /** CRL Distribution Points (old) OID */
    private static final String CRL_DISTRIBUTION_POINTS_OLD_OID = "2.5.29.25"; // Old - not to do?

    /** Delta CRL Indicator OID */
    private static final String DELTA_CRL_INDICATOR_OID = "2.5.29.27";

    /** Issuing Distribution Point OID */
    private static final String ISSUING_DISTRIBUTION_POINT_OID = "2.5.29.28"; // Std todo

    /** Certificate Issuer OID */
    private static final String CERTIFICATE_ISSUER_OID = "2.5.29.29";

    /** Name Constraints OID */
    private static final String NAME_CONSTRAINTS_OID = "2.5.29.30"; // Std todo

    /** CRL Distribution Points OID */
    private static final String CRL_DISTRIBUTION_POINTS_OID = "2.5.29.31"; // Std todo

    /** Certificate Policies OID */
    private static final String CERTIFICATE_POLICIES_OID = "2.5.29.32"; // Std todo

    /** Policy Mappings OID */
    private static final String POLICY_MAPPINGS_OID = "2.5.29.33";

    /** Policy Constraints (old) OID */
    private static final String POLICY_CONSTRAINTS_OLD_OID = "2.5.29.34"; // Old - not to do?

    /** Authority Key Identifier OID */
    private static final String AUTHORITY_KEY_IDENTIFIER_OID = "2.5.29.35";

    /** Policy Constraints OID */
    private static final String POLICY_CONSTRAINTS_OID = "2.5.29.36";

    /** Extended Key Usage OID */
    private static final String EXTENDED_KEY_USAGE_OID = "2.5.29.37";

    /** CRL Stream Identifier OID */
    private static final String CRL_STREAM_IDENTIFIER_OID = "2.5.29.40"; // No info available

    /** CRL Scope OID */
    private static final String CRL_SCOPE_OID = "2.5.29.44"; // No info available

    /** Status Referrals OID */
    private static final String STATUS_REFERRALS_OID = "2.5.29.45"; // No info available

    /** Freshest CRL OID */
    private static final String FRESHEST_CRL_OID = "2.5.29.46"; // Std todo

    /** Ordered List OID */
    private static final String ORDERED_LIST_OID = "2.5.29.47"; // No info available

    /** Base Update Time OID */
    private static final String BASE_UPDATE_TIME_OID = "2.5.29.51"; // No info available

    /** Delta Information OID */
    private static final String DELTA_INFORMATION_OID = "2.5.29.53"; // No info available

    /** Inhibit Any Policy OID */
    private static final String INHIBIT_ANY_POLICY_OID = "2.5.29.54";

    /** Netscape Certificate Type OID */
    private static final String NETSCAPE_CERTIFICATE_TYPE_OID = "2.16.840.1.113730.1.1";

    /** Netscape Base URL OID */
    private static final String NETSCAPE_BASE_URL_OID = "2.16.840.1.113730.1.2";

    /** Netscape Revocation URL OID */
    private static final String NETSCAPE_REVOCATION_URL_OID = "2.16.840.1.113730.1.3";

    /** Netscape CA Revocation URL OID */
    private static final String NETSCAPE_CA_REVOCATION_URL_OID = "2.16.840.1.113730.1.4";

    /** Netscape Certificate Renewal URL OID */
    private static final String NETSCAPE_CERTIFICATE_RENEWAL_URL_OID = "2.16.840.1.113730.1.7";

    /** Netscape CA Policy URL OID */
    private static final String NETSCAPE_CA_POLICY_URL_OID = "2.16.840.1.113730.1.8";

    /** Netscape SSL Server Name OID */
    private static final String NETSCAPE_SSL_SERVER_NAME_OID = "2.16.840.1.113730.1.12";

    /** Netscape Comment OID */
    private static final String NETSCAPE_COMMENT_OID = "2.16.840.1.113730.1.13";

    /////////////////////////////////////////////
    // Reason codes (2.5.29.21)
    /////////////////////////////////////////////

    /** Unspecified Reason Code */
    private static final int UNSPECIFIED_REASONCODE = 0;

    /** Key Compromise Reason Code  */
    private static final int KEY_COMPROMISE_REASONCODE = 1;

    /** CA Compromise Reason Code  */
    private static final int CA_COMPROMISE_REASONCODE = 2;

    /** Affiliation Changed Reason Code */
    private static final int AFFILIATION_CHANGED_REASONCODE = 3;

    /** Superseded Reason Code */
    private static final int SUPERSEDED_REASONCODE = 4;

    /** Cessation of Operation Reason Code */
    private static final int CESSATION_OF_OPERATION_REASONCODE = 5;

    /** Certificate Hold Reason Code */
    private static final int CERTIFICATE_HOLD_REASONCODE = 6;

    /** Remove from CRL Reason Code */
    private static final int REMOVE_FROM_CRL_REASONCODE = 8;

    /** Privilege Withdrawn Reason Code */
    private static final int PRIVILEGE_WITHDRAWN_REASONCODE = 9;

    /** AA Compromise Reason Code */
    private static final int AA_COMPROMISE_REASONCODE = 10;

    /////////////////////////////////////////////
    // Hold Instruction Code OIDs (2.5.29.23)
    /////////////////////////////////////////////

    /** Hold Instruction Code None OID */
    private static final String HOLD_INSTRUCTION_CODE_NONE_OID = "1.2.840.10040.2.1";

    /** Hold Instruction Code None OID */
    private static final String HOLD_INSTRUCTION_CODE_CALL_ISSUER_OID = "1.2.840.10040.2.2";

    /** Hold Instruction Code None OID */
    private static final String HOLD_INSTRUCTION_CODE_REJECT_OID = "1.2.840.10040.2.3";

    /////////////////////////////////////////////
    // Extended Key Usage OIDs (2.5.29.37)
    /////////////////////////////////////////////

    /** TLS Web Server Authentication Extended Key Usage OID */
    private static final String SERVERAUTH_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.1";

    /** TLS Web Client Authentication Extended Key Usage OID */
    private static final String CLIENTAUTH_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.2";

    /** Code Signing Extended Key Usage OID */
    private static final String CODESIGNING_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.3";

    /** E-mail Protection Extended Key Usage OID */
    private static final String EMAILPROTECTION_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.4";

    /** IP Security End System Extended Key Usage OID */
    private static final String IPSECENDSYSTEM_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.5";

    /** IP Security Tunnel termination Extended Key Usage OID */
    private static final String IPSECENDTUNNEL_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.6";

    /** IP Security User Extended Key Usage OID */
    private static final String IPSECUSER_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.7";

    /** Time Stamping Extended Key Usage OID */
    private static final String TIMESTAMPING_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.8";

    /** OCSP Stamping Extended Key Usage OID */
    private static final String OCSPSIGNING_EXT_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.9";

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

        m_sName = lookupName();
    }

    /**
     * Lookup the extension's "friendly" name.
     *
     * @return Extension name or null if name is unknown
     */
    private String lookupName()
    {
        // Compare OID to known OIDs for which we have names - set name accordingly
        if (m_sOid.equals(AUTHORITY_KEY_IDENTIFIER_OID))
        {
            return m_res.getString("AuthorityKeyIdentifierCertExtString");
        }
        else if (m_sOid.equals(AUTHORITY_KEY_IDENTIFIER_OLD_OID))
        {
            return m_res.getString("AuthorityKeyIdentifierOldCertExtString");
        }
        else if (m_sOid.equals(BASE_UPDATE_TIME_OID))
        {
            return m_res.getString("BaseUpdateTimeCertExtString");
        }
        else if (m_sOid.equals(BASIC_CONSTRAINTS_OID))
        {
            return m_res.getString("BasicConstraintsCertExtString");
        }
        else if (m_sOid.equals(BASIC_CONSTRAINTS_OLD_0_OID))
        {
            return m_res.getString("BasicConstraintsOld0CertExtString");
        }
        else if (m_sOid.equals(BASIC_CONSTRAINTS_OLD_1_OID))
        {
            return m_res.getString("BasicConstraintsOld1CertExtString");
        }
        else if (m_sOid.equals(CERTIFICATE_ISSUER_OID))
        {
            return m_res.getString("CertificateIssuerCertExtString");
        }
        else if (m_sOid.equals(CERTIFICATE_POLICIES_OID))
        {
            return m_res.getString("CertificatePoliciesCertExtString");
        }
        else if (m_sOid.equals(CERTIFICATE_POLICIES_OLD_OID))
        {
            return m_res.getString("CertificatePoliciesOldCertExtString");
        }
        else if (m_sOid.equals(CRL_DISTRIBUTION_POINTS_OID))
        {
            return m_res.getString("CrlDistributionPointsCertExtString");
        }
        else if (m_sOid.equals(CRL_DISTRIBUTION_POINTS_OLD_OID))
        {
            return m_res.getString("CrlDistributionPointsOldCertExtString");
        }
        else if (m_sOid.equals(CRL_NUMBER_OID))
        {
            return m_res.getString("CrlNumberCertExtString");
        }
        else if (m_sOid.equals(CRL_SCOPE_OID))
        {
            return m_res.getString("CrlScopeCertExtString");
        }
        else if (m_sOid.equals(CRL_STREAM_IDENTIFIER_OID))
        {
            return m_res.getString("CrlStreamIdentifierCertExtString");
        }
        else if (m_sOid.equals(DELTA_CRL_INDICATOR_OID))
        {
            return m_res.getString("DeltaCrlIndicatorCertExtString");
        }
        else if (m_sOid.equals(DELTA_INFORMATION_OID))
        {
            return m_res.getString("DeltaInformationCertExtString");
        }
        else if (m_sOid.equals(EXTENDED_KEY_USAGE_OID))
        {
            return m_res.getString("ExtendedKeyUsageCertExtString");
        }
        else if (m_sOid.equals(FRESHEST_CRL_OID))
        {
            return m_res.getString("FreshestCrlCertExtString");
        }
        else if (m_sOid.equals(HOLD_INSTRUCTION_CODE_OID))
        {
            return m_res.getString("HoldInstructionCodeCertExtString");
        }
        else if (m_sOid.equals(INHIBIT_ANY_POLICY_OID))
        {
            return m_res.getString("InhibitAnyPolicyCertExtString");
        }
        else if (m_sOid.equals(INVALIDITY_DATE_OID))
        {
            return m_res.getString("InvalidityDateCertExtString");
        }
        else if (m_sOid.equals(ISSUER_ALTERNATIVE_NAME_OID))
        {
            return m_res.getString("IssuerAlternativeNameCertExtString");
        }
        else if (m_sOid.equals(ISSUING_DISTRIBUTION_POINT_OID))
        {
            return m_res.getString("IssuingDistributionPointCertExtString");
        }
        else if (m_sOid.equals(KEY_USAGE_OID))
        {
            return m_res.getString("KeyUsageCertExtString");
        }
        else if (m_sOid.equals(NAME_CONSTRAINTS_OID))
        {
            return m_res.getString("NameConstraintsCertExtString");
        }
        else if (m_sOid.equals(ORDERED_LIST_OID))
        {
            return m_res.getString("OrderedListCertExtString");
        }
        else if (m_sOid.equals(POLICY_CONSTRAINTS_OID))
        {
            return m_res.getString("PolicyConstraintsCertExtString");
        }
        else if (m_sOid.equals(POLICY_CONSTRAINTS_OLD_OID))
        {
            return m_res.getString("PolicyConstraintsOldCertExtString");
        }
        else if (m_sOid.equals(POLICY_MAPPINGS_OID))
        {
            return m_res.getString("PolicyMappingsCertExtString");
        }
        else if (m_sOid.equals(PRIMARY_KEY_ATTRIBUTES_OID))
        {
            return m_res.getString("PrimaryKeyAttributesCertExtString");
        }
        else if (m_sOid.equals(PRIMARY_KEY_USAGE_RESTRICTION_OID))
        {
            return m_res.getString("PrimaryKeyUsageRestrictionCertExtString");
        }
        else if (m_sOid.equals(PRIVATE_KEY_USAGE_PERIOD_OID))
        {
            return m_res.getString("PrivateKeyUsagePeriodCertExtString");
        }
        else if (m_sOid.equals(REASON_CODE_OID))
        {
            return m_res.getString("ReasonCodeCertExtString");
        }
        else if (m_sOid.equals(STATUS_REFERRALS_OID))
        {
            return m_res.getString("StatusReferralsCertExtString");
        }
        else if (m_sOid.equals(SUBJECT_ALTERNATIVE_NAME_OID))
        {
            return m_res.getString("SubjectAlternativeNameCertExtString");
        }
        else if (m_sOid.equals(SUBJECT_DIRECTORY_ATTRIBUTES_OID))
        {
            return m_res.getString("SubjectDirectoryAttributesCertExtString");
        }
        else if (m_sOid.equals(SUBJECT_KEY_IDENTIFIER_OID))
        {
            return m_res.getString("SubjectKeyIdentifierCertExtString");
        }
        else if (m_sOid.equals(NETSCAPE_CERTIFICATE_TYPE_OID))
        {
            return m_res.getString("NetscapeCertificateTypeExtString");
        }
        else if (m_sOid.equals(NETSCAPE_BASE_URL_OID))
        {
            return m_res.getString("NetscapeBaseUrlExtString");
        }
        else if (m_sOid.equals(NETSCAPE_REVOCATION_URL_OID))
        {
            return m_res.getString("NetscapeRevocationUrlExtString");
        }
        else if (m_sOid.equals(NETSCAPE_CA_REVOCATION_URL_OID))
        {
            return m_res.getString("NetscapeCaRevocationUrlExtString");
        }
        else if (m_sOid.equals(NETSCAPE_CERTIFICATE_RENEWAL_URL_OID))
        {
            return m_res.getString("NetscapeCertificateRenewalUrlExtString");
        }
        else if (m_sOid.equals(NETSCAPE_CA_POLICY_URL_OID))
        {
            return m_res.getString("NetscapeCaPolicyUrlExtString");
        }
        else if (m_sOid.equals(NETSCAPE_SSL_SERVER_NAME_OID))
        {
            return m_res.getString("NetscapeSslServerNameExtString");
        }
        else if (m_sOid.equals(NETSCAPE_COMMENT_OID))
        {
            return m_res.getString("NetscapeCommentExtString");
        }
        else
        {
            // OID not known
            return null;
        }
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
        ASN1InputStream ais = null;
        byte[] bOctets = null;

        try
        {
            ais = new ASN1InputStream(new ByteArrayInputStream(m_bValue));

            DEROctetString derOctStr = (DEROctetString)ais.readObject();

            bOctets = derOctStr.getOctets();
        }
        finally
        {
            try { if (ais != null)  ais.close(); } catch (IOException ex) { /* Ignore */ }
        }

        // Octet string processed differently depending on extension type
        if (m_sOid.equals(SUBJECT_KEY_IDENTIFIER_OID)) // 2.5.29.14
        {
            return getSubjectKeyIndentifierStringValue(bOctets);
        }
        else if (m_sOid.equals(KEY_USAGE_OID)) // 2.5.29.15
        {
            return getKeyUsageStringValue(bOctets);
        }
        else if (m_sOid.equals(PRIVATE_KEY_USAGE_PERIOD_OID)) // 2.5.29.16
        {
            return getPrivateKeyUsagePeriod(bOctets);
        }
        else if (m_sOid.equals(SUBJECT_ALTERNATIVE_NAME_OID)) // 2.5.29.17
        {
            return getSubjectAlternativeName(bOctets);
        }
        else if (m_sOid.equals(ISSUER_ALTERNATIVE_NAME_OID)) // 2.5.29.18
        {
            return getIssuerAlternativeName(bOctets);
        }
        else if (m_sOid.equals(BASIC_CONSTRAINTS_OID)) // 2.5.29.19
        {
            return getBasicConstraintsStringValue(bOctets);
        }
        else if (m_sOid.equals(CRL_NUMBER_OID)) // 2.5.29.20
        {
            return getCrlNumberStringValue(bOctets);
        }
        else if (m_sOid.equals(REASON_CODE_OID)) // 2.5.29.21
        {
            return getReasonCodeStringValue(bOctets);
        }
        else if (m_sOid.equals(HOLD_INSTRUCTION_CODE_OID)) // 2.5.29.23
        {
            return getHoldInstructionCodeStringValue(bOctets);
        }
        else if (m_sOid.equals(INVALIDITY_DATE_OID)) // 2.5.29.24
        {
            return getInvalidityDateStringValue(bOctets);
        }
        else if (m_sOid.equals(DELTA_CRL_INDICATOR_OID)) // 2.5.29.27
        {
            return getDeltaCrlIndicatorStringValue(bOctets);
        }
        else if (m_sOid.equals(CERTIFICATE_ISSUER_OID)) // 2.5.29.29
        {
            return getCertificateIssuerStringValue(bOctets);
        }
        else if (m_sOid.equals(POLICY_MAPPINGS_OID)) // 2.5.29.33
        {
            return getPolicyMappingsStringValue(bOctets);
        }
        else if (m_sOid.equals(AUTHORITY_KEY_IDENTIFIER_OID)) // 2.5.29.35
        {
            return getAuthorityKeyIdentifierStringValue(bOctets);
        }

        else if (m_sOid.equals(POLICY_CONSTRAINTS_OID)) // 2.5.29.36
        {
            return getPolicyConstraintsStringValue(bOctets);
        }

        else if (m_sOid.equals(EXTENDED_KEY_USAGE_OID)) // 2.5.29.37
        {
            return getExtendedKeyUsageStringValue(bOctets);
        }
        else if (m_sOid.equals(INHIBIT_ANY_POLICY_OID)) // 2.5.29.54
        {
            return getInhibitAnyPolicyStringValue(bOctets);
        }
        else if (m_sOid.equals(NETSCAPE_CERTIFICATE_TYPE_OID)) // 2.16.840.1.113730.1.1
        {
            return getNetscapeCertificateTypeStringValue(bOctets);
        }
        // 2.16.840.1.113730.1.x where x is one of 2, 3, 4, 6, 7, 12 or 13
        else if ((m_sOid.equals(NETSCAPE_BASE_URL_OID)) || (m_sOid.equals(NETSCAPE_REVOCATION_URL_OID)) ||
                 (m_sOid.equals(NETSCAPE_CA_REVOCATION_URL_OID)) || (m_sOid.equals(NETSCAPE_CERTIFICATE_RENEWAL_URL_OID)) ||
                 (m_sOid.equals(NETSCAPE_CA_POLICY_URL_OID)) || (m_sOid.equals(NETSCAPE_SSL_SERVER_NAME_OID)) ||
                 (m_sOid.equals(NETSCAPE_COMMENT_OID)))
        {
            return getNonNetscapeCertificateTypeStringValue(bOctets);
        }

        // Don't know how to process the extension - just dump out hex and clear text
        else
        {
            ByteArrayInputStream bais = null;

            try
            {
                // Divide dump into 8 byte lines
                StringBuffer strBuff = new StringBuffer();

                bais = new ByteArrayInputStream(bOctets);
                byte[] bLine = new byte[8];
                int iRead = -1;

                while ((iRead = bais.read(bLine)) != -1)
                {
                    strBuff.append(getHexClearDump(bLine, iRead));
                }

                return strBuff.toString();
            }
            finally
            {
                try { if (bais != null)  bais.close(); } catch (IOException ex) { /* Ignore */ }
            }
        }
    }

    /**
     * Get Subject Key Indentifier (2.5.29.14) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getSubjectKeyIndentifierStringValue(byte[] bValue) throws IOException
    {
        /* SubjectKeyIdentifier ::= KeyIdentifier

           KeyIdentifier ::= OCTET STRING */

        DERInputStream dis = null;

        try
        {
            // Get key identifier
            dis = new DERInputStream(new ByteArrayInputStream(bValue));
            DEROctetString derOctetStr = (DEROctetString)dis.readObject();

            byte[] bKeyIdent = derOctetStr.getOctets();

            // Output as a hex string
            StringBuffer strBuff = new StringBuffer();
            strBuff.append(convertToHexString(bKeyIdent));
            strBuff.append('\n');
            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get Key Usage (2.5.29.15) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getKeyUsageStringValue(byte[] bValue) throws IOException
    {
        /* KeyUsage ::= BIT STRING {
               digitalSignature        (0),
               nonRepudiation          (1),
               keyEncipherment         (2),
               dataEncipherment        (3),
               keyAgreement            (4),
               keyCertSign             (5),
               cRLSign                 (6),
               encipherOnly            (7),
               decipherOnly            (8) } */

        DERInputStream dis = null;

        try
        {
            // Get bit string
            dis = new DERInputStream(new ByteArrayInputStream(bValue));
            DERBitString derBitStr = (DERBitString)dis.readObject();

            StringBuffer strBuff = new StringBuffer();

            byte[] bytes = derBitStr.getBytes();

            boolean bKeyAgreement = false;

            // Loop through bit string appending them to the returned string value as flags are found true
            for (int iCnt=0; iCnt < bytes.length; iCnt++)
            {
                boolean[] b = new boolean[8];

                b[7] = ((bytes[iCnt] & 0x80) == 0x80);
                b[6] = ((bytes[iCnt] & 0x40) == 0x40);
                b[5] = ((bytes[iCnt] & 0x20) == 0x20);
                b[4] = ((bytes[iCnt] & 0x10) == 0x10);
                b[3] = ((bytes[iCnt] & 0x8) == 0x8);
                b[2] = ((bytes[iCnt] & 0x4) == 0x4);
                b[1] = ((bytes[iCnt] & 0x2) == 0x2);
                b[0] = ((bytes[iCnt] & 0x1) == 0x1);

                // First byte
                if (iCnt == 0)
                {
                    if (b[7] == true)
                    {
                        strBuff.append(m_res.getString("DigitalSignatureKeyUsageString"));
                        strBuff.append('\n');
                    }

                    if (b[6] == true)
                    {
                        strBuff.append(m_res.getString("NonRepudiationKeyUsageString"));
                        strBuff.append('\n');
                    }

                    if (b[5] == true)
                    {
                        strBuff.append(m_res.getString("KeyEnciphermentKeyUsageString"));
                        strBuff.append('\n');
                    }

                    if (b[4] == true)
                    {
                        strBuff.append(m_res.getString("DataEnciphermentKeyUsageString"));
                        strBuff.append('\n');
                    }

                    if (b[3] == true)
                    {
                        strBuff.append(m_res.getString("KeyAgreementKeyUsageString"));
                        strBuff.append('\n');
                        bKeyAgreement = true;
                    }

                    if (b[2] == true)
                    {
                        strBuff.append(m_res.getString("KeyCertSignKeyUsageString"));
                        strBuff.append('\n');
                    }

                    if (b[1] == true)
                    {
                        strBuff.append(m_res.getString("CrlSignKeyUsageString"));
                        strBuff.append('\n');
                    }

                    if ((b[0] == true) && bKeyAgreement) // Only has meaning if key agreement set
                    {
                        strBuff.append(m_res.getString("EncipherOnlyKeyUsageString"));
                        strBuff.append('\n');
                    }
                }
                // Second byte
                else if (iCnt == 1)
                {
                    if ((b[7] == true) && bKeyAgreement) // Only has meaning if key agreement set
                    {
                        strBuff.append(m_res.getString("DecipherOnlyKeyUsageString"));
                        strBuff.append('\n');
                    }
                }
            }

            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get Private Key Usage Period (2.5.29.16) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     * @throws ParseException If a date formatting problem occurs
     */
    private String getPrivateKeyUsagePeriod(byte[] bValue) throws IOException, ParseException
    {
        /* PrivateKeyUsagePeriod ::= SEQUENCE {
               notBefore       [0]     GeneralizedTime OPTIONAL,
               notAfter        [1]     GeneralizedTime OPTIONAL } */

        DERInputStream dis = null;

        try
        {
            // Get sequence of "not before" and "not after" times
            dis = new DERInputStream(new ByteArrayInputStream(bValue));
            ASN1Sequence times = (ASN1Sequence)dis.readObject();

            StringBuffer strBuff = new StringBuffer();

            for (Enumeration enumTimes = times.getObjects(); enumTimes.hasMoreElements();)
            {
                DERTaggedObject derTag = (DERTaggedObject)enumTimes.nextElement();

                if (derTag.getTagNo() == 0) // Output "not before" time
                {
                    DEROctetString notBefore = (DEROctetString)derTag.getObject();
                    DERGeneralizedTime notBeforeTime = new DERGeneralizedTime(new String(notBefore.getOctets()));
                    strBuff.append(MessageFormat.format(m_res.getString("NotBeforePrivateKeyUsagePeriod"), new String[]{formatGeneralizedTime(notBeforeTime)}));
                    strBuff.append('\n');
                }
                else if (derTag.getTagNo() == 1) // Output "not after" time
                {
                    DEROctetString notAfter = (DEROctetString)derTag.getObject();
                    DERGeneralizedTime notAfterTime = new DERGeneralizedTime(new String(notAfter.getOctets()));
                    strBuff.append(MessageFormat.format(m_res.getString("NotAfterPrivateKeyUsagePeriod"), new String[]{formatGeneralizedTime(notAfterTime)}));
                    strBuff.append('\n');
                }
            }

            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get Subject Alternative Name (2.5.29.17) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getSubjectAlternativeName(byte[] bValue) throws IOException
    {
        /* SubjectAltName ::= GeneralNames

           GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName */

        DERInputStream dis = null;

        try
        {
            // Get sequence of general names
            dis = new DERInputStream(new ByteArrayInputStream(bValue));
            ASN1Sequence generalNames = (ASN1Sequence)dis.readObject();

            StringBuffer strBuff = new StringBuffer();

            for (Enumeration enumGN = generalNames.getObjects(); enumGN.hasMoreElements();)
            {
                DERTaggedObject generalName = (DERTaggedObject)enumGN.nextElement();

                strBuff.append(getGeneralNameString(generalName));
                strBuff.append('\n');
            }

            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get Issuer Alternative Name (2.5.29.18) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getIssuerAlternativeName(byte[] bValue) throws IOException
    {
        /* SubjectAltName ::= GeneralNames

           GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName */

        DERInputStream dis = null;

        try
        {
            StringBuffer strBuff = new StringBuffer();

            // Get sequence of general names
            dis = new DERInputStream(new ByteArrayInputStream(bValue));
            ASN1Sequence generalNames = (ASN1Sequence)dis.readObject();

            for (Enumeration enumGN = generalNames.getObjects(); enumGN.hasMoreElements();)
            {
                DERTaggedObject generalName = (DERTaggedObject)enumGN.nextElement();
                strBuff.append(getGeneralNameString(generalName));
                strBuff.append('\n');
            }

            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get Basic Constraints (2.5.29.19) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getBasicConstraintsStringValue(byte[] bValue) throws IOException
    {
        /* BasicConstraints ::= SEQUENCE {
               cA                      BOOLEAN DEFAULT FALSE,
               pathLenConstraint       INTEGER (0..MAX) OPTIONAL } */

        DERInputStream dis = null;

        try
        {
            // Get sequence
            dis = new DERInputStream(new ByteArrayInputStream(bValue));
            ASN1Sequence asn1Seq = (ASN1Sequence)dis.readObject();

            // Default values when none specified in sequence
            boolean bCa = false;
            int iPathLengthConstraint = -1;

            if (asn1Seq.size() > 0) // Read CA boolean if present in sequence
            {
                DERBoolean derBool = (DERBoolean)asn1Seq.getObjectAt(0);
                bCa = derBool.isTrue();
            }

            if (asn1Seq.size() > 1) // Read Path Length Constraint boolean if present in sequence
            {
                DERInteger derInt = (DERInteger)asn1Seq.getObjectAt(1);
                iPathLengthConstraint = derInt.getValue().intValue();
            }

            // Output information
            StringBuffer strBuff = new StringBuffer();

            // Subject is CA?
            if (bCa)
            {
                strBuff.append(m_res.getString("SubjectIsCa"));
            }
            else
            {
                strBuff.append(m_res.getString("SubjectIsNotCa"));
            }
            strBuff.append('\n');

            // Path length constraint (only has meaning when CA is true)
            if ((iPathLengthConstraint != -1) && (bCa))
            {
                strBuff.append(MessageFormat.format(m_res.getString("PathLengthConstraint"), new String[]{""+iPathLengthConstraint}));
            }
            else
            {
                strBuff.append(m_res.getString("NoPathLengthConstraint"));
            }
            strBuff.append('\n');

            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get CRL Number (2.5.29.20) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getCrlNumberStringValue(byte[] bValue) throws IOException
    {
        /* CRLNumber ::= INTEGER (0..MAX) */

        DERInputStream dis = null;

        try
        {
            // Get CRL number
            dis = new DERInputStream(new ByteArrayInputStream(bValue));
            DERInteger derInt = (DERInteger)dis.readObject();

            // Convert to and return hex string representation of number
            StringBuffer strBuff = new StringBuffer();

            strBuff.append(convertToHexString(derInt));
            strBuff.append('\n');
            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get Reason Code (2.5.29.21) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getReasonCodeStringValue(byte[] bValue) throws IOException
    {
        /* ReasonCode ::= { CRLReason }

           CRLReason ::= ENUMERATED {
               unspecified             (0),
               keyCompromise           (1),
               cACompromise            (2),
               affiliationChanged      (3),
               superseded              (4),
               cessationOfOperation    (5),
               certificateHold         (6),
               removeFromCRL           (8),
               privilegeWithdrawn      (9),
               aACompromise           (10) } */

        DERInputStream dis = null;

        try
        {
            // Get reason code enumeration and return appropriate string
            dis = new DERInputStream(new ByteArrayInputStream(bValue));

            DEREnumerated derEnum = (DEREnumerated)dis.readObject();

            BigInteger reasonCode = derEnum.getValue();

            int iReasonCode = reasonCode.intValue();
            String sReasonCodeString = null;

            if (iReasonCode == UNSPECIFIED_REASONCODE)
            {
                sReasonCodeString = m_res.getString("UnspecifiedReasonCodeString");
            }
            else if (iReasonCode == KEY_COMPROMISE_REASONCODE)
            {
                sReasonCodeString = m_res.getString("KeyCompromiseReasonCodeString");
            }
            else if (iReasonCode == CA_COMPROMISE_REASONCODE)
            {
                sReasonCodeString = m_res.getString("CaCompromiseReasonCodeString");
            }
            else if (iReasonCode == AFFILIATION_CHANGED_REASONCODE)
            {
                sReasonCodeString = m_res.getString("AffiliationChangedReasonCodeString");
            }
            else if (iReasonCode == SUPERSEDED_REASONCODE)
            {
                sReasonCodeString = m_res.getString("SupersededReasonCodeString");
            }
            else if (iReasonCode == CESSATION_OF_OPERATION_REASONCODE)
            {
                sReasonCodeString = m_res.getString("CessationOfOperationReasonCodeString");
            }
            else if (iReasonCode == CERTIFICATE_HOLD_REASONCODE)
            {
                sReasonCodeString = m_res.getString("CertificateHoldReasonCodeString");
            }
            else if (iReasonCode == REMOVE_FROM_CRL_REASONCODE)
            {
                sReasonCodeString = m_res.getString("RemoveFromCrlReasonCodeString");
            }
            else if (iReasonCode == PRIVILEGE_WITHDRAWN_REASONCODE)
            {
                sReasonCodeString = m_res.getString("PrivilegeWithdrawnReasonCodeString");
            }
            else if (iReasonCode == AA_COMPROMISE_REASONCODE)
            {
                sReasonCodeString = m_res.getString("AaCompromiseReasonCodeString");
            }
            else
            {
                sReasonCodeString = m_res.getString("UnrecognisedReasonCodeString");
            }

            // Place Reason Code in string
            StringBuffer strBuff = new StringBuffer();
            strBuff.append(MessageFormat.format(sReasonCodeString, new String[]{""+iReasonCode}));
            strBuff.append('\n');
            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get Hold Instruction Code (2.5.29.23) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getHoldInstructionCodeStringValue(byte[] bValue) throws IOException
    {
        /* HoldInstructionCode ::= OBJECT IDENTIFER */

        DERInputStream dis = null;

        try
        {
            // Get Hold Instruction Code OID
            dis = new DERInputStream(new ByteArrayInputStream(bValue));
            DERObjectIdentifier holdInstructionCode = (DERObjectIdentifier)dis.readObject();
            String sHoldInstructionCode = holdInstructionCode.getId();

            StringBuffer strBuff = new StringBuffer();

            if (sHoldInstructionCode.equals(HOLD_INSTRUCTION_CODE_NONE_OID))
            {
                strBuff.append(MessageFormat.format(m_res.getString("HoldInstructionCodeNone"), new String[]{sHoldInstructionCode}));
            }
            else if (sHoldInstructionCode.equals(HOLD_INSTRUCTION_CODE_CALL_ISSUER_OID))
            {
                strBuff.append(MessageFormat.format(m_res.getString("HoldInstructionCodeCallIssuer"), new String[]{sHoldInstructionCode}));
            }
            else if (sHoldInstructionCode.equals(HOLD_INSTRUCTION_CODE_REJECT_OID))
            {
                strBuff.append(MessageFormat.format(m_res.getString("HoldInstructionCodeReject"), new String[]{sHoldInstructionCode}));
            }
            else // Unrecognised Hold Instruction Code OIDderObj
            {
                strBuff.append(sHoldInstructionCode);
            }
            strBuff.append('\n');

            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get Invalidity Date (2.5.29.24) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     * @throws ParseException If a date formatting problem occurs
     */
    private String getInvalidityDateStringValue(byte[] bValue) throws IOException, ParseException
    {
        /* InvalidityDate ::=  GeneralizedTime */

        DERInputStream dis = null;

        try
        {
            // Get invalidity date
            dis = new DERInputStream(new ByteArrayInputStream(bValue));
            DERGeneralizedTime invalidityDate = (DERGeneralizedTime)dis.readObject();

            // Format invalidity date for display
            String sInvalidityTime = formatGeneralizedTime(invalidityDate);

            StringBuffer strBuff = new StringBuffer();
            strBuff.append(sInvalidityTime);
            strBuff.append('\n');
            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get Delta CRL Indicator (2.5.29.27) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getDeltaCrlIndicatorStringValue(byte[] bValue) throws IOException
    {
        /* BaseCRLNumber ::= CRLNumber

           CRLNumber ::= INTEGER (0..MAX)  */

        DERInputStream dis = null;

        try
        {
            // Get CRL number
            dis = new DERInputStream(new ByteArrayInputStream(bValue));
            DERInteger derInt = (DERInteger)dis.readObject();

            // Convert to and return hex string representation of number
            StringBuffer strBuff = new StringBuffer();
            strBuff.append(convertToHexString(derInt));
            strBuff.append('\n');
            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get Certificate Issuer (2.5.29.29) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getCertificateIssuerStringValue(byte[] bValue) throws IOException
    {
        /* certificateIssuer ::= GeneralNames

           GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName */

        DERInputStream dis = null;

        try
        {
            StringBuffer strBuff = new StringBuffer();

            // Get sequence of general names
            dis = new DERInputStream(new ByteArrayInputStream(bValue));
            ASN1Sequence generalNames = (ASN1Sequence)dis.readObject();

            for (Enumeration enumGN = generalNames.getObjects(); enumGN.hasMoreElements();)
            {
                DERTaggedObject generalName = (DERTaggedObject)enumGN.nextElement();

                strBuff.append(getGeneralNameString(generalName));
                strBuff.append('\n');
            }

            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get Policy Mappings (2.5.29.33) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getPolicyMappingsStringValue(byte[] bValue) throws IOException
    {
        /*  PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
                issuerDomainPolicy      CertPolicyId,
                subjectDomainPolicy     CertPolicyId }

            CertPolicyId ::= OBJECT IDENTIFIER */

        DERInputStream dis = null;

        try
        {
            // Get sequence of policy mappings
            dis = new DERInputStream(new ByteArrayInputStream(bValue));
            ASN1Sequence policyMappings = (ASN1Sequence)dis.readObject();

            StringBuffer strBuff = new StringBuffer();

            // Get each policy mapping
            int iCnt = 1;
            for (Enumeration enumPM = policyMappings.getObjects(); enumPM.hasMoreElements();)
            {
                ASN1Sequence policyMapping = (ASN1Sequence)enumPM.nextElement();

                strBuff.append(MessageFormat.format(m_res.getString("PolicyMapping"), new String[]{""+iCnt}));
                strBuff.append('\n');

                if (policyMapping.size() > 0) // Policy mapping issuer domain policy
                {
                    DERObjectIdentifier issuerDomainPolicy = (DERObjectIdentifier)policyMapping.getObjectAt(0);
                    strBuff.append('\t');
                    strBuff.append(MessageFormat.format(m_res.getString("IssuerDomainPolicy"), new String[]{issuerDomainPolicy.getId()}));
                    strBuff.append('\n');
                }

                if (policyMapping.size() > 1) // Policy mapping subject domain policy
                {
                    DERObjectIdentifier subjectDomainPolicy = (DERObjectIdentifier)policyMapping.getObjectAt(1);
                    strBuff.append('\t');
                    strBuff.append(MessageFormat.format(m_res.getString("SubjectDomainPolicy"), new String[]{subjectDomainPolicy.getId()}));
                    strBuff.append('\n');
                }

                iCnt++;
            }

            strBuff.append('\n');

            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get Authority Key Identifier (2.5.29.35) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getAuthorityKeyIdentifierStringValue(byte[] bValue) throws IOException
    {
        /*
           AuthorityKeyIdentifier ::= SEQUENCE {
               keyIdentifier             [0] KeyIdentifier           OPTIONAL,
               authorityCertIssuer       [1] Names                   OPTIONAL,
               authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL }

           KeyIdentifier ::= OCTET STRING

           GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

           CertificateSerialNumber  ::=  INTEGER */

        DERInputStream dis = null;

        try
        {
            /* Get sequence of (all optional) a key identifier, an authority
               cert issuer names and an authority cert serial number */
            dis = new DERInputStream(new ByteArrayInputStream(bValue));

            ASN1Sequence asn1Seq = (ASN1Sequence)dis.readObject();

            DEROctetString keyIdentifier = null;
            ASN1Sequence authorityCertIssuer = null;
            DEROctetString certificateSerialNumber = null;

            for (int iCnt=0; iCnt < asn1Seq.size(); iCnt++)
            {
                DERTaggedObject derTagObj = (DERTaggedObject)asn1Seq.getObjectAt(iCnt);

                int iTagNo = derTagObj.getTagNo();

                DERObject derObj = (DERObject)derTagObj.getObject();

                if (iTagNo == 0) // Key Identifier
                {
                    keyIdentifier = (DEROctetString)derObj;
                }
                else if (iTagNo == 1) // Authority Cert Issuer
                {
                    // Many general names
                    if (derObj instanceof ASN1Sequence)
                    {
                        authorityCertIssuer = (ASN1Sequence)derObj;
                    }
                    // One general name
                    else
                    {
                        authorityCertIssuer = new DERSequence(derObj);
                    }
                }
                else if (iTagNo == 2) // Certificate Serial Number
                {
                    certificateSerialNumber = (DEROctetString)derObj;
                }
            }

            StringBuffer strBuff = new StringBuffer();

            if (keyIdentifier != null) // If present get Key Identifier as a string
            {
                // Get key identifier from octet string
                byte[] bKeyIdent = keyIdentifier.getOctets();

                // Output as a hex string
                strBuff.append(MessageFormat.format(m_res.getString("KeyIdentifier"), new String[]{convertToHexString(bKeyIdent)}));
                strBuff.append('\n');
            }

            if (authorityCertIssuer != null) // If present get Authority Cert Issuer as a string
            {
                strBuff.append(m_res.getString("CertificateIssuer"));
                strBuff.append('\n');

                for (Enumeration enumACI = authorityCertIssuer.getObjects(); enumACI.hasMoreElements();)
                {
                    DERTaggedObject generalName = (DERTaggedObject)enumACI.nextElement();
                    strBuff.append('\t');
                    strBuff.append(getGeneralNameString(generalName));
                    strBuff.append('\n');
                }
            }

            if (certificateSerialNumber != null) // If present get Certificate Serial Number as a string
            {
                // Get certificate serial number from octet string
                byte[] bCertSerialNumber = certificateSerialNumber.getOctets();

                // Output as a hex string
                strBuff.append(MessageFormat.format(m_res.getString("CertificateSerialNumber"), new String[]{convertToHexString(bCertSerialNumber)}));
                strBuff.append('\n');
            }

            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get Policy Constraints (2.5.29.36) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getPolicyConstraintsStringValue(byte[] bValue) throws IOException
    {
        /*  PolicyConstraints ::= SEQUENCE {
                requireExplicitPolicy           [0] SkipCerts OPTIONAL,
                inhibitPolicyMapping            [1] SkipCerts OPTIONAL }

            SkipCerts ::= INTEGER (0..MAX) */

        DERInputStream dis = null;

        try
        {
            // Get sequence of policy constraint
            dis = new DERInputStream(new ByteArrayInputStream(bValue));
            ASN1Sequence policyConstraints = (ASN1Sequence)dis.readObject();

            StringBuffer strBuff = new StringBuffer();

            for (Enumeration enumPC = policyConstraints.getObjects(); enumPC.hasMoreElements();)
            {
                // Get skip certs for policy constraint
                DERTaggedObject policyConstraint = (DERTaggedObject)enumPC.nextElement();
                DERInteger skipCerts = new DERInteger(((DEROctetString)policyConstraint.getObject()).getOctets());
                int iSkipCerts = skipCerts.getValue().intValue();

                if (policyConstraint.getTagNo() == 0) // Require Explicit Policy Skip Certs
                {
                    strBuff.append(MessageFormat.format(m_res.getString("RequireExplicitPolicy"), new String[]{""+iSkipCerts}));
                    strBuff.append('\n');
                }
                else if (policyConstraint.getTagNo() == 1) // Inhibit Policy Mapping Skip Certs
                {
                    strBuff.append(MessageFormat.format(m_res.getString("InhibitPolicyMapping"), new String[]{""+iSkipCerts}));
                    strBuff.append('\n');
                }
            }

            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get Extended Key Usage (2.5.29.37) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getExtendedKeyUsageStringValue(byte[] bValue) throws IOException
    {
        /* ExtendedKeyUsage ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId

           KeyPurposeId ::= OBJECT IDENTIFIER */

        DERInputStream dis = null;

        try
        {
            // Get sequence of OIDs and return approriate strings
            dis = new DERInputStream(new ByteArrayInputStream(bValue));
            ASN1Sequence asn1Seq = (ASN1Sequence)dis.readObject();

            StringBuffer strBuff = new StringBuffer();

            for (int iCnt=0; iCnt < asn1Seq.size(); iCnt++)
            {
                DERObjectIdentifier derOid = (DERObjectIdentifier)asn1Seq.getObjectAt(iCnt);
                String sOid = derOid.getId();
                String sExtKeyUsage = null;

                if (sOid.equals(SERVERAUTH_EXT_KEY_USAGE_OID))
                {
                    sExtKeyUsage = m_res.getString("ServerAuthExtKeyUsageString");
                }
                else if (sOid.equals(CLIENTAUTH_EXT_KEY_USAGE_OID))
                {
                    sExtKeyUsage = m_res.getString("ClientAuthExtKeyUsageString");
                }
                else if (sOid.equals(CODESIGNING_EXT_KEY_USAGE_OID))
                {
                    sExtKeyUsage = m_res.getString("CodeSigningExtKeyUsageString");
                }
                else if (sOid.equals(EMAILPROTECTION_EXT_KEY_USAGE_OID))
                {
                    sExtKeyUsage = m_res.getString("EmailProtectionExtKeyUsageString");
                }
                else if (sOid.equals(IPSECENDSYSTEM_EXT_KEY_USAGE_OID))
                {
                    sExtKeyUsage = m_res.getString("IpsecEndSystemExtKeyUsageString");
                }
                else if (sOid.equals(IPSECENDTUNNEL_EXT_KEY_USAGE_OID))
                {
                    sExtKeyUsage = m_res.getString("IpsecTunnelExtKeyUsageString");
                }
                else if (sOid.equals(IPSECUSER_EXT_KEY_USAGE_OID))
                {
                    sExtKeyUsage = m_res.getString("IpsecUserExtKeyUsageString");
                }
                else if (sOid.equals(TIMESTAMPING_EXT_KEY_USAGE_OID))
                {
                    sExtKeyUsage = m_res.getString("TimeStampingExtKeyUsageString");
                }
                else if (sOid.equals(OCSPSIGNING_EXT_KEY_USAGE_OID))
                {
                    sExtKeyUsage = m_res.getString("OcspSigningExtKeyUsageString");
                }
                else
                {
                    sExtKeyUsage = m_res.getString("UnrecognisedExtKeyUsageString");
                }

                // Place OID in string
                strBuff.append(MessageFormat.format(sExtKeyUsage, new String[]{sOid}));
                strBuff.append('\n');
            }

            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get Inhibit Any Policy (2.5.29.54) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getInhibitAnyPolicyStringValue(byte[] bValue) throws IOException
    {
        /* InhibitAnyPolicy ::= SkipCerts

           SkipCerts ::= INTEGER (0..MAX) */

        DERInputStream dis = null;

        try
        {
            // Get skip certs integer
            dis = new DERInputStream(new ByteArrayInputStream(bValue));
            DERInteger skipCerts = (DERInteger)dis.readObject();

            int iSkipCerts = skipCerts.getValue().intValue();

            // Return inhibit any policy extension
            StringBuffer strBuff = new StringBuffer();
            strBuff.append(MessageFormat.format(m_res.getString("InhibitAnyPolicy"), new String[]{""+iSkipCerts}));
            strBuff.append('\n');
            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get Netscape Certificate Type (2.16.840.1.113730.1.1) extension value as a string.
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getNetscapeCertificateTypeStringValue(byte[] bValue) throws IOException
    {
        DERInputStream dis = null;

        try
        {
            // Get bits
            dis = new DERInputStream(new ByteArrayInputStream(bValue));
            DERBitString derBitStr = (DERBitString)dis.readObject();

            StringBuffer strBuff = new StringBuffer();

            byte[] bytes = derBitStr.getBytes();

            boolean bKeyAgreement = false;

            if (bytes.length > 0)
            {
                boolean[] b = new boolean[8];

                b[7] = ((bytes[0] & 0x80) == 0x80);
                b[6] = ((bytes[0] & 0x40) == 0x40);
                b[5] = ((bytes[0] & 0x20) == 0x20);
                b[4] = ((bytes[0] & 0x10) == 0x10);
                b[3] = ((bytes[0] & 0x8) == 0x8);
                b[2] = ((bytes[0] & 0x4) == 0x4);
                b[1] = ((bytes[0] & 0x2) == 0x2);
                b[0] = ((bytes[0] & 0x1) == 0x1);

                if (b[7] == true)
                {
                    strBuff.append(m_res.getString("SslClientNetscapeCertificateType"));
                    strBuff.append('\n');
                }

                if (b[6] == true)
                {
                    strBuff.append(m_res.getString("SslServerNetscapeCertificateType"));
                    strBuff.append('\n');
                }

                if (b[5] == true)
                {
                    strBuff.append(m_res.getString("SmimeNetscapeCertificateType"));
                    strBuff.append('\n');
                }

                if (b[4] == true)
                {
                    strBuff.append(m_res.getString("ObjectSigningNetscapeCertificateType"));
                    strBuff.append('\n');
                    bKeyAgreement = true;
                }

                if (b[2] == true)
                {
                    strBuff.append(m_res.getString("SslCaNetscapeCertificateType"));
                    strBuff.append('\n');
                }

                if (b[1] == true)
                {
                    strBuff.append(m_res.getString("SmimeCaNetscapeCertificateType"));
                    strBuff.append('\n');
                }

                if (b[0] == true)
                {
                    strBuff.append(m_res.getString("ObjectSigningCaNetscapeCertificateType"));
                    strBuff.append('\n');
                }
            }

            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get extension value for any Netscape certificate extension that is *not* Certificate Type
     * as a string. (2.16.840.1.113730.1.x, where x can be any of 2, 3, 4, 7, 8, 12 or 13).
     *
     * @param bValue The octet string value
     * @return Extension value as a string
     * @throws IOException If an I/O problem occurs
     */
    private String getNonNetscapeCertificateTypeStringValue(byte[] bValue) throws IOException
    {
        DERInputStream dis = null;

        try
        {
            // Get and return string
            dis = new DERInputStream(new ByteArrayInputStream(bValue));
            DERIA5String derStr = (DERIA5String)dis.readObject();

            StringBuffer strBuff = new StringBuffer();

            strBuff.append(derStr.getString());
            strBuff.append('\n');
            return strBuff.toString();
        }
        finally
        {
            try { if (dis != null)  dis.close(); } catch (IOException ex) { /* Ignore */ }
        }
    }

    /**
     * Get the supplied general name as a string ([general name type]=[general name]).
     *
     * @param generalName The general name
     * @return General name string
     */
    private String getGeneralNameString(DERTaggedObject generalName)
    {
        /* GeneralName ::= CHOICE {
               otherName                       [0]     OtherName,
               rfc822Name                      [1]     IA5String, x
               dNSName                         [2]     IA5String, x
               x400Address                     [3]     ORAddress,
               directoryName                   [4]     Name, x
               ediPartyName                    [5]     EDIPartyName,
               uniformResourceIdentifier       [6]     IA5String, x
               iPAddress                       [7]     OCTET STRING, x
               registeredID                    [8]     OBJECT IDENTIFIER x }

           OtherName ::= SEQUENCE {
               type-id    OBJECT IDENTIFIER,
               value      [0] EXPLICIT ANY DEFINED BY type-id }

           EDIPartyName ::= SEQUENCE {
               nameAssigner            [0]     DirectoryString OPTIONAL,
               partyName               [1]     DirectoryString }

           DirectoryString ::= CHOICE {
               teletexString           TeletexString (SIZE (1..maxSize),
               printableString         PrintableString (SIZE (1..maxSize)),
               universalString         UniversalString (SIZE (1..maxSize)),
               utf8String              UTF8String (SIZE (1.. MAX)),
               bmpString               BMPString (SIZE(1..maxSIZE)) }*/

        StringBuffer strBuff = new StringBuffer();

        int iTagNo = generalName.getTagNo();

        if (iTagNo == 1)  // RFC 822 Name
        {
            DEROctetString rfc822 = (DEROctetString)generalName.getObject();
            String sRfc822 = new String(rfc822.getOctets());
            strBuff.append(MessageFormat.format(m_res.getString("Rfc822GeneralName"), new String[]{sRfc822}));
        }
        else if (iTagNo == 2)  // DNS Name
        {
            DEROctetString dns = (DEROctetString)generalName.getObject();
            String sDns = new String(dns.getOctets());
            strBuff.append(MessageFormat.format(m_res.getString("DnsGeneralName"), new String[]{sDns}));
        }
        else if (iTagNo == 4) // Directory Name
        {
            ASN1Sequence directory = (ASN1Sequence)generalName.getObject();
            X509Name name = new X509Name(directory);
            strBuff.append(MessageFormat.format(m_res.getString("DirectoryGeneralName"), new String[]{name.toString()}));
        }
        else if (iTagNo == 6) // URI
        {
            DEROctetString uri = (DEROctetString)generalName.getObject();
            String sUri = new String(uri.getOctets());
            strBuff.append(MessageFormat.format(m_res.getString("UriGeneralName"), new String[]{sUri}));
        }
        else if (iTagNo == 7) // IP Address
        {
            DEROctetString ipAddress = (DEROctetString)generalName.getObject();

            byte[] bIpAddress = ipAddress.getOctets();

            // Output the IP Address components one at a time separated by dots
            StringBuffer sbIpAddress = new StringBuffer();

            for (int iCnt=0; iCnt < bIpAddress.length; iCnt++)
            {
                byte b = bIpAddress[iCnt];

                // Convert from (possibly negative) byte to positive int
                sbIpAddress.append((int) b & 0xFF);

                if ((iCnt+1) < bIpAddress.length)
                {
                    sbIpAddress.append('.');
                }
            }

            strBuff.append(MessageFormat.format(m_res.getString("IpAddressGeneralName"), new String[]{sbIpAddress.toString()}));
        }
        else if (iTagNo == 8) // Registered ID
        {
            DEROctetString registeredId = (DEROctetString)generalName.getObject();

            byte[] bRegisteredId = registeredId.getOctets();

            // Output the Registered ID components one at a time separated by dots
            StringBuffer sbRegisteredId = new StringBuffer();

            for (int iCnt=0; iCnt < bRegisteredId.length; iCnt++)
            {
                byte b = bRegisteredId[iCnt];

                // Convert from (possibly negative) byte to positive int
                sbRegisteredId.append((int)b & 0xFF);

                if ((iCnt+1) < bRegisteredId.length)
                {
                    sbRegisteredId.append('.');
                }
            }

            strBuff.append(MessageFormat.format(m_res.getString("RegisteredIdGeneralName"), new String[]{sbRegisteredId.toString()}));

        }
        else // Unsupported general name type
        {
            strBuff.append(MessageFormat.format(m_res.getString("UnsupportedGeneralNameType"), new String[]{""+iTagNo}));
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
    private String formatGeneralizedTime(DERGeneralizedTime time) throws ParseException
    {
        // Get generalized time as a string
        String sTime = time.getTime();

        // Setup date formatter with expected date format of string
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmssz");

        // Create date object from string using formatter
        Date date = dateFormat.parse(sTime);

        // Re-format date - include timezone
        sTime = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.LONG).format((Date)date);

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

            // Character to display if character not define din Unicode or is a contorl charcter
            char c = '.';

            // Not a control character and defined in Unicode
            if ((!Character.isISOControl((char)i)) && (Character.isDefined((char)i)))
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
    private String convertToHexString(DERInteger derInt)
    {
        // Convert number to hex string - divide string with a space every four characters
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
    private String convertToHexString(byte[] bytes)
    {
        // Convert to hex
        StringBuffer strBuff = new StringBuffer(new BigInteger(1, bytes).toString(16).toUpperCase());

        // Place spaces at every four hex characters
        if (strBuff.length() > 4)
        {
            for (int iCnt=4; iCnt < strBuff.length(); iCnt+=5)
            {
                strBuff.insert(iCnt, ' ');
            }
        }

        return strBuff.toString();
    }
}
