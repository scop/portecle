/*
 * DGenerateCertificate.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
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

package net.sf.portecle;

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import java.security.*;
import java.security.cert.X509Certificate;

import net.sf.portecle.crypto.*;
import net.sf.portecle.gui.error.DThrowable;

/**
 * Dialog used to generate a certificate based on a supplied key pair
 * and signature algorithm for inclusion in a KeyStore.  Allows the
 * user to enter the signature algorithm and validty period of the
 * certificate in days as well as all of the certificate attributes of
 * a version 1 X.509 certificate.  The choice of available signature
 * algorithms depends on the key pair generation algorithm selected.
 */
class DGenerateCertificate extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Signature Algorithm label */
    private JLabel m_jlSigAlg;

    /** Signature Algoritm combo box */
    private JComboBox m_jcbSigAlg;

    /** Validity label */
    private JLabel m_jlValidity;

    /** Validity text field */
    private JTextField m_jtfValidity;

    /** Common Name label */
    private JLabel m_jlCommonName;

    /** Common Name text field */
    private JTextField m_jtfCommonName;

    /** Organisation Unit label */
    private JLabel m_jlOrganisationUnit;

    /** Organisation Unit text field */
    private JTextField m_jtfOrganisationUnit;

    /** Organisation Name label */
    private JLabel m_jlOrganisationName;

    /** Organisation Unit Name */
    private JTextField m_jtfOrganisationName;

    /** Locality Name label */
    private JLabel m_jlLocalityName;

    /** Locality Name text field */
    private JTextField m_jtfLocalityName;

    /** State Name label */
    private JLabel m_jlStateName;

    /** State Name text field */
    private JTextField m_jtfStateName;

    /** Country Code label */
    private JLabel m_jlCountryCode;

    /** Country Code test field */
    private JTextField m_jtfCountryCode;

    /** Email Address label */
    private JLabel m_jlEmailAddress;

    /** Email Address text field */
    private JTextField m_jtfEmailAddress;

    /** Panel containing all of the entry controls */
    private JPanel m_jpOptions;

    /** Panel for confirmation button controls */
    private JPanel m_jpButtons;

    /** OK button to confirm dialog */
    private JButton m_jbOK;

    /** Cancel button to cancel dialog */
    private JButton m_jbCancel;

    /** The key pair to generate the certificate from */
    private KeyPair m_keyPair;

    /** The key pair type */
    private KeyPairType m_keyPairType;

    /** Generated certificate */
    private X509Certificate m_certificate;

    /** Key from input map to action map for the cancel button */
    private static final String CANCEL_KEY = "CANCEL_KEY";

    /** Indicator used for a bad validity period */
    private static final int BAD_VALIDITY = -1;

    /** Dummy password to use for PKCS #12 KeyStore entries (passwords
     * are not applicable for these) */
    private static final char[] PKCS12_DUMMY_PASSWORD = "dummy".toCharArray();

    /**
     * Creates new form DGenerateCertificate where the parent is a frame.
     *
     * @param parent The parent frame
     * @param sTitle The dialog's title
     * @param bModal Is dialog modal?
     * @param keyPair The key pair to generate the certificate from
     * @param keyPairType The key pair type
     */
    public DGenerateCertificate(JFrame parent, String sTitle, boolean bModal,
                                KeyPair keyPair, KeyPairType keyPairType)
    {
        super(parent, bModal);
        m_keyPair = keyPair;
        m_keyPairType = keyPairType;
        initComponents(sTitle);
    }

    /**
     * Initialise the dialog's GUI components.
     *
     * @param sTitle The dialog's title
     */
    private void initComponents(String sTitle)
    {
        // Grid Bag Constraints templates for labels and editable controls
        GridBagConstraints gbcLbl = new GridBagConstraints();
        gbcLbl.gridx = 0;
        gbcLbl.gridwidth = 3;
        gbcLbl.gridheight = 1;
        gbcLbl.insets = new Insets(5, 5, 5, 5);
        gbcLbl.anchor = GridBagConstraints.EAST;

        GridBagConstraints gbcEdCtrl = new GridBagConstraints();
        gbcEdCtrl.gridx = 3;
        gbcEdCtrl.gridwidth = 3;
        gbcEdCtrl.gridheight = 1;
        gbcEdCtrl.insets = new Insets(5, 5, 5, 5);
        gbcEdCtrl.anchor = GridBagConstraints.WEST;

        // Signature Algorithm
        m_jlSigAlg = new JLabel(
            m_res.getString("DGenerateCertificate.m_jlSigAlg.text"));
        GridBagConstraints gbc_jlSigAlg = (GridBagConstraints)gbcLbl.clone();
        gbc_jlSigAlg.gridy = 0;

        m_jcbSigAlg = new JComboBox();
        populateSigAlgs();
        m_jcbSigAlg.setToolTipText(
            m_res.getString("DGenerateCertificate.m_jcbSigAlg.tooltip"));
        m_jcbSigAlg.setSelectedIndex(0);
        GridBagConstraints gbc_jcbSigAlg =
            (GridBagConstraints) gbcEdCtrl.clone();
        gbc_jcbSigAlg.gridy = 0;

        // Validity Period
        m_jlValidity = new JLabel(
            m_res.getString("DGenerateCertificate.m_jlValidity.text"));
        GridBagConstraints gbc_jlValidity = (GridBagConstraints)gbcLbl.clone();
        gbc_jlValidity.gridy = 1;

        m_jtfValidity = new JTextField(4);
        m_jtfValidity.setToolTipText(
            m_res.getString("DGenerateCertificate.m_jtfValidity.tooltip"));
        GridBagConstraints gbc_jtfValidity =
            (GridBagConstraints) gbcEdCtrl.clone();
        gbc_jtfValidity.gridy = 1;

        // Common Name
        m_jlCommonName = new JLabel(
            m_res.getString("DGenerateCertificate.m_jlCommonName.text"));
        GridBagConstraints gbc_jlCommonName =
            (GridBagConstraints) gbcLbl.clone();
        gbc_jlCommonName.gridy = 2;

        m_jtfCommonName = new JTextField(15);
        m_jtfCommonName.setToolTipText(
            m_res.getString("DGenerateCertificate.m_jtfCommonName.tooltip"));
        GridBagConstraints gbc_jtfCommonName =
            (GridBagConstraints) gbcEdCtrl.clone();
        gbc_jtfCommonName.gridy = 2;

        // Organisation Unit
        m_jlOrganisationUnit = new JLabel(
            m_res.getString("DGenerateCertificate.m_jlOrganisationUnit.text"));
        GridBagConstraints gbc_jlOrganisationUnit =
            (GridBagConstraints) gbcLbl.clone();
        gbc_jlOrganisationUnit.gridy = 3;

        m_jtfOrganisationUnit = new JTextField(15);
        m_jtfOrganisationUnit.setToolTipText(
            m_res.getString(
                "DGenerateCertificate.m_jtfOrganisationUnit.tooltip"));
        GridBagConstraints gbc_jtfOrganisationUnit =
            (GridBagConstraints) gbcEdCtrl.clone();
        gbc_jtfOrganisationUnit.gridy = 3;

        // Organisation Name
        m_jlOrganisationName = new JLabel(
            m_res.getString("DGenerateCertificate.m_jlOrganisationName.text"));
        GridBagConstraints gbc_jlOrganisationName =
            (GridBagConstraints) gbcLbl.clone();
        gbc_jlOrganisationName.gridy = 4;

        m_jtfOrganisationName = new JTextField(15);
        m_jtfOrganisationName.setToolTipText(
            m_res.getString(
                "DGenerateCertificate.m_jtfOrganisationName.tooltip"));
        GridBagConstraints gbc_jtfOrganisationName =
            (GridBagConstraints) gbcEdCtrl.clone();
        gbc_jtfOrganisationName.gridy = 4;

        // Locality Name
        m_jlLocalityName = new JLabel(
            m_res.getString("DGenerateCertificate.m_jlLocalityName.text"));
        GridBagConstraints gbc_jlLocalityName =
            (GridBagConstraints) gbcLbl.clone();
        gbc_jlLocalityName.gridy = 5;

        m_jtfLocalityName = new JTextField(15);
        m_jtfLocalityName.setToolTipText(
            m_res.getString("DGenerateCertificate.m_jtfLocalityName.tooltip"));
        GridBagConstraints gbc_jtfLocalityName =
            (GridBagConstraints) gbcEdCtrl.clone();
        gbc_jtfLocalityName.gridy = 5;

        // State Name
        m_jlStateName = new JLabel(
            m_res.getString("DGenerateCertificate.m_jlStateName.text"));
        GridBagConstraints gbc_jlStateName =
            (GridBagConstraints) gbcLbl.clone();
        gbc_jlStateName.gridy = 6;

        m_jtfStateName = new JTextField(15);
        m_jtfStateName.setToolTipText(
            m_res.getString("DGenerateCertificate.m_jtfStateName.tooltip"));
        GridBagConstraints gbc_jtfStateName =
            (GridBagConstraints) gbcEdCtrl.clone();
        gbc_jtfStateName.gridy = 6;

        // Country Code
        m_jlCountryCode = new JLabel(
            m_res.getString("DGenerateCertificate.m_jlCountryCode.text"));
        GridBagConstraints gbc_jlCountryCode =
            (GridBagConstraints) gbcLbl.clone();
        gbc_jlCountryCode.gridy = 7;

        m_jtfCountryCode = new JTextField(4);
        m_jtfCountryCode.setToolTipText(
            m_res.getString("DGenerateCertificate.m_jtfCountryCode.tooltip"));
        GridBagConstraints gbc_jtfCountryCode =
            (GridBagConstraints) gbcEdCtrl.clone();
        gbc_jtfCountryCode.gridy = 7;

        // Email Address
        m_jlEmailAddress = new JLabel(
            m_res.getString("DGenerateCertificate.m_jlEmailAddress.text"));
        GridBagConstraints gbc_jlEmailAddress =
            (GridBagConstraints) gbcLbl.clone();
        gbc_jlEmailAddress.gridy = 8;

        m_jtfEmailAddress = new JTextField(15);
        m_jtfEmailAddress.setToolTipText(
            m_res.getString("DGenerateCertificate.m_jtfEmailAddress.tooltip"));
        GridBagConstraints gbc_jtfEmailAddress =
            (GridBagConstraints) gbcEdCtrl.clone();
        gbc_jtfEmailAddress.gridy = 8;

        // Put it all together
        m_jpOptions = new JPanel(new GridBagLayout());
        m_jpOptions.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5),
                                                 new EtchedBorder()));

        m_jpOptions.add(m_jlSigAlg, gbc_jlSigAlg);
        m_jpOptions.add(m_jcbSigAlg, gbc_jcbSigAlg);
        m_jpOptions.add(m_jlValidity, gbc_jlValidity);
        m_jpOptions.add(m_jtfValidity, gbc_jtfValidity);
        m_jpOptions.add(m_jlCommonName, gbc_jlCommonName);
        m_jpOptions.add(m_jtfCommonName, gbc_jtfCommonName);
        m_jpOptions.add(m_jlOrganisationUnit, gbc_jlOrganisationUnit);
        m_jpOptions.add(m_jtfOrganisationUnit, gbc_jtfOrganisationUnit);
        m_jpOptions.add(m_jlOrganisationName, gbc_jlOrganisationName);
        m_jpOptions.add(m_jtfOrganisationName, gbc_jtfOrganisationName);
        m_jpOptions.add(m_jlLocalityName, gbc_jlLocalityName);
        m_jpOptions.add(m_jtfLocalityName, gbc_jtfLocalityName);
        m_jpOptions.add(m_jlStateName, gbc_jlStateName);
        m_jpOptions.add(m_jtfStateName, gbc_jtfStateName);
        m_jpOptions.add(m_jlCountryCode, gbc_jlCountryCode);
        m_jpOptions.add(m_jtfCountryCode, gbc_jtfCountryCode);
        m_jpOptions.add(m_jlEmailAddress, gbc_jlEmailAddress);
        m_jpOptions.add(m_jtfEmailAddress, gbc_jtfEmailAddress);

        m_jbOK = new JButton(
            m_res.getString("DGenerateCertificate.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        m_jbCancel = new JButton(
            m_res.getString("DGenerateCertificate.m_jbCancel.text"));
        m_jbCancel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });
        m_jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);
        m_jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction () {
                public void actionPerformed(ActionEvent evt) {
                    cancelPressed();
                }});

        m_jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
        m_jpButtons.add(m_jbOK);
        m_jpButtons.add(m_jbCancel);

        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(m_jpOptions, BorderLayout.CENTER);
        getContentPane().add(m_jpButtons, BorderLayout.SOUTH);

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        setTitle(sTitle);
        setResizable(false);

        getRootPane().setDefaultButton(m_jbOK);

        pack();
    }

    /**
     * Populate the signature algorithm combo box with the signature algorithms
     * applicable to the key pair algorithm.
     */
    private void populateSigAlgs()
    {
        Object sigAlgs[];

        if (m_keyPairType == KeyPairType.DSA)
        {
            sigAlgs = new Object[]{SignatureType.DSA_SHA1};

        }
        else
        {
            sigAlgs = new Object[]{SignatureType.RSA_MD2,
                                   SignatureType.RSA_MD5,
                                   SignatureType.RSA_SHA1};
        }

        m_jcbSigAlg.removeAllItems();

        for (int iCnt=0; iCnt < sigAlgs.length; iCnt++)
        {
            m_jcbSigAlg.addItem(sigAlgs[iCnt]);
        }
        m_jcbSigAlg.setSelectedIndex(0);
    }


    /**
     * Generate a certificate based on the parameters supplied to the dialog
     * and the user entry.
     *
     * @return True if the certificate generation is successful, false
     * otherwise
     */
    private boolean generateCertificate()
    {
        // Validate dialog's field values
        int iValidity = validateValidity(m_jtfValidity.getText());
        String sCommonName = validateCommonName(m_jtfCommonName.getText());
        String sOrganisationUnit =
            validateOrganisationUnit(m_jtfOrganisationUnit.getText());
        String sOrganisationName =
            validateOrganisationName(m_jtfOrganisationName.getText());
        String sLocalityName =
            validateLocalityName(m_jtfLocalityName.getText());
        String sStateName = validateStateName(m_jtfStateName.getText());
        String sCountryCode = validateCountryCode(m_jtfCountryCode.getText());
        String sEmailAddress =
            validateEmailAddress(m_jtfEmailAddress.getText());

        if (iValidity == BAD_VALIDITY)
        {
            return false;
        }

        if ((sCommonName == null) && (sOrganisationUnit == null) &&
            (sOrganisationName == null) && (sLocalityName == null) &&
            (sStateName == null) && (sCountryCode == null) &&
            (sEmailAddress == null))
        {
            JOptionPane.showMessageDialog(
                this,
                m_res.getString(
                    "DGenerateCertificate.ValueReqCertAttr.message"),
                getTitle(),
                JOptionPane.WARNING_MESSAGE);
            return false;
        }

        // Country code must be two characters long
        if ((sCountryCode != null) && (sCountryCode.length() != 2))
        {
            JOptionPane.showMessageDialog(
                this,
                m_res.getString(
                    "DGenerateCertificate.CountryCodeTwoChars.message"),
                getTitle(),
                JOptionPane.WARNING_MESSAGE);
            return false;
        }

        // Generate certificate...

        try
        {
            SignatureType signatureType =
                (SignatureType) m_jcbSigAlg.getSelectedItem();
            m_certificate = X509CertUtil.generateCert(
                sCommonName, sOrganisationUnit, sOrganisationName,
                sLocalityName, sStateName, sCountryCode,
                sEmailAddress, iValidity, m_keyPair.getPublic(),
                m_keyPair.getPrivate(), signatureType
            );
        }
        catch (CryptoException ex)
        {
            DThrowable dThrowable = new DThrowable(this, true, ex);
            dThrowable.setLocationRelativeTo(getParent());
            dThrowable.setVisible(true);
            closeDialog();
        }

        return true;
    }

    /**
     * Validate the Validity value supplied as a string and convert it to an
     * integer.
     *
     * @param sValidity The Validity value
     * @return The Validity value or BAD_VALIDITY if it is not valid
     */
    private int validateValidity(String sValidity)
    {
        sValidity = sValidity.trim();
        int iValidity;

        if (sValidity.length() == 0)
        {
            JOptionPane.showMessageDialog(
                this,
                m_res.getString("DGenerateCertificate.ValReqValidity.message"),
                getTitle(),
                JOptionPane.WARNING_MESSAGE);
            return BAD_VALIDITY;
        }

        try
        {
            iValidity = Integer.parseInt(sValidity);
        }
        catch (NumberFormatException ex)
        {
            JOptionPane.showMessageDialog(
                this,
                m_res.getString(
                    "DGenerateCertificate.ValidityInteger.message"),
                getTitle(),
                JOptionPane.WARNING_MESSAGE);
            return BAD_VALIDITY;
        }

        if (iValidity < 1)
        {
            JOptionPane.showMessageDialog(
                this,
                m_res.getString(
                    "DGenerateCertificate.ValidityNonZero.message"),
                getTitle(),
                JOptionPane.WARNING_MESSAGE);
            return BAD_VALIDITY;
        }

        return iValidity;
    }

    /**
     * Validate the supplied Common Name value.
     *
     * @param sCommonName The Validity value
     * @return The Common Name value or null if it is not valid
     */
    private String validateCommonName(String sCommonName)
    {
        sCommonName = sCommonName.trim();

        if (sCommonName.length() < 1)
        {
            return null;
        }

        return sCommonName;

    }

    /**
     * Validate the supplied Organisation Unit value.
     *
     * @param sOrganisationUnit The Organisation Unit value
     * @return The Organisation Unit value or null if it is not valid
     */
    private String validateOrganisationUnit(String sOrganisationUnit)
    {
        sOrganisationUnit = sOrganisationUnit.trim();

        if (sOrganisationUnit.length() < 1)
        {
            return null;
        }

        return sOrganisationUnit;
    }

    /**
     * Validate the supplied Organisation Name value.
     *
     * @param sOrganisationName The Organisation Unit value
     * @return The Organisation Name value or null if it is not valid
     */
    private String validateOrganisationName(String sOrganisationName)
    {
        sOrganisationName = sOrganisationName.trim();

        if (sOrganisationName.length() < 1)
        {
            return null;
        }

        return sOrganisationName;
    }

    /**
     * Validate the supplied Locality Name value.
     *
     * @param sLocalityName The Locality Name value
     * @return The Locality Name value or null if it is not valid
     */
    private String validateLocalityName(String sLocalityName)
    {
        sLocalityName = sLocalityName.trim();

        if (sLocalityName.length() < 1)
        {
            return null;
        }

        return sLocalityName;
    }

    /**
     * Validate the supplied State Name value.
     *
     * @param sStateName The State Name value
     * @return The State Name value or null if it is not valid
     */
    private String validateStateName(String sStateName)
    {
        sStateName = sStateName.trim();

        if (sStateName.length() < 1)
        {
            return null;
        }

        return sStateName;
    }

    /**
     * Validate the supplied Country Code value.
     *
     * @param sCountryCode The Country Code value
     * @return The Country Code value or null if it is not valid
     */
    private String validateCountryCode(String sCountryCode)
    {
        sCountryCode = sCountryCode.trim();

        if (sCountryCode.length() < 1)
        {
            return null;
        }

        return sCountryCode;
    }

    /**
     * Validate the supplied Email Address value.
     *
     * @param sEmailAddress The Email Address value
     * @return The Email Address value or null if it is not valid
     */
    private String validateEmailAddress(String sEmailAddress)
    {
        sEmailAddress = sEmailAddress.trim();

        if (sEmailAddress.length() < 1)
        {
            return null;
        }

        return sEmailAddress;
    }

    /**
     * Get the generated certificate.
     *
     * @return The generated certificate or null if the user cancelled
     * the dialog
     */
    public X509Certificate getCertificate()
    {
        return m_certificate;
    }

    /**
     * OK button pressed or otherwise activated.
     */
    private void okPressed()
    {
        if (generateCertificate())
        {
            closeDialog();
        }
    }

    /**
     * Cancel button pressed or otherwise activated.
     */
    private void cancelPressed()
    {
        closeDialog();
    }

    /**
     * Closes the dialog.
     */
    private void closeDialog()
    {
        setVisible(false);
        dispose();
    }
}
