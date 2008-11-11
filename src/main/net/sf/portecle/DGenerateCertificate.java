/*
 * DGenerateCertificate.java
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

package net.sf.portecle;

import static net.sf.portecle.FPortecle.RB;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Locale;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.text.AbstractDocument;
import javax.swing.text.Document;

import net.sf.portecle.crypto.CryptoException;
import net.sf.portecle.crypto.KeyPairType;
import net.sf.portecle.crypto.SignatureType;
import net.sf.portecle.crypto.X509CertUtil;
import net.sf.portecle.gui.DocumentMaxLengthFilter;
import net.sf.portecle.gui.IntegerDocumentFilter;
import net.sf.portecle.gui.SwingHelper;
import net.sf.portecle.gui.error.DThrowable;

/**
 * Dialog used to generate a certificate based on a supplied key pair and signature algorithm for inclusion in
 * a keystore. Allows the user to enter the signature algorithm and validty period of the certificate in days
 * as well as all of the certificate attributes of a version 1 X.509 certificate. The choice of available
 * signature algorithms depends on the key pair generation algorithm selected.
 */
class DGenerateCertificate
    extends JDialog
{
	/** Key from input map to action map for the cancel button */
	private static final String CANCEL_KEY = "CANCEL_KEY";

	/** Indicator used for a bad validity period */
	private static final int BAD_VALIDITY = -1;

	/** Required country code length in characters */
	private static final int COUNTRY_CODE_LENGTH = 2;

	/** Default validity period */
	private static final String DEFAULT_VALIDITY = RB.getString("DGenerateCertificate.defaultValidityPeriod");

	/** Signature Algorithm combo box */
	private JComboBox m_jcbSigAlg;

	/** Validity text field */
	private JTextField m_jtfValidity;

	/** Common Name text field */
	private JTextField m_jtfCommonName;

	/** Organisation Unit text field */
	private JTextField m_jtfOrganisationUnit;

	/** Organisation Unit Name */
	private JTextField m_jtfOrganisationName;

	/** Locality Name text field */
	private JTextField m_jtfLocalityName;

	/** State Name text field */
	private JTextField m_jtfStateName;

	/** Country Code text field */
	private JTextField m_jtfCountryCode;

	/** Email Address text field */
	private JTextField m_jtfEmailAddress;

	/** The key pair to generate the certificate from */
	private KeyPair m_keyPair;

	/** The key pair type */
	private KeyPairType m_keyPairType;

	/** Generated certificate */
	private X509Certificate m_certificate;

	/**
	 * Creates new DGenerateCertificate dialog.
	 * 
	 * @param parent The parent window
	 * @param sTitle The dialog's title
	 * @param modal Is dialog modal?
	 * @param keyPair The key pair to generate the certificate from
	 * @param keyPairType The key pair type
	 */
	public DGenerateCertificate(Window parent, String sTitle, boolean modal, KeyPair keyPair,
	    KeyPairType keyPairType)
	{
		super(parent, (modal ? Dialog.DEFAULT_MODALITY_TYPE : Dialog.ModalityType.MODELESS));
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

		int gridy = 0;

		// Signature Algorithm
		JLabel jlSigAlg = new JLabel(RB.getString("DGenerateCertificate.jlSigAlg.text"));
		GridBagConstraints gbc_jlSigAlg = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSigAlg.gridy = gridy++;

		m_jcbSigAlg = new JComboBox();
		populateSigAlgs(m_keyPairType, m_jcbSigAlg);
		m_jcbSigAlg.setToolTipText(RB.getString("DGenerateCertificate.m_jcbSigAlg.tooltip"));
		GridBagConstraints gbc_jcbSigAlg = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jcbSigAlg.gridy = gbc_jlSigAlg.gridy;

		// Validity Period
		JLabel jlValidity = new JLabel(RB.getString("DGenerateCertificate.jlValidity.text"));
		GridBagConstraints gbc_jlValidity = (GridBagConstraints) gbcLbl.clone();
		gbc_jlValidity.gridy = gridy++;

		m_jtfValidity = new JTextField(DEFAULT_VALIDITY, 5);
		Document doc = m_jtfValidity.getDocument();
		if (doc instanceof AbstractDocument)
		{
			((AbstractDocument) doc).setDocumentFilter(new IntegerDocumentFilter(m_jtfValidity.getColumns()));
		}
		m_jtfValidity.setToolTipText(RB.getString("DGenerateCertificate.m_jtfValidity.tooltip"));
		GridBagConstraints gbc_jtfValidity = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jtfValidity.gridy = gbc_jlValidity.gridy;

		// Common Name
		JLabel jlCommonName = new JLabel(RB.getString("DGenerateCertificate.jlCommonName.text"));
		GridBagConstraints gbc_jlCommonName = (GridBagConstraints) gbcLbl.clone();
		gbc_jlCommonName.gridy = gridy++;

		m_jtfCommonName = new JTextField(15);
		m_jtfCommonName.setToolTipText(RB.getString("DGenerateCertificate.m_jtfCommonName.tooltip"));
		GridBagConstraints gbc_jtfCommonName = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jtfCommonName.gridy = gbc_jlCommonName.gridy;

		// Organisation Unit
		JLabel jlOrganisationUnit = new JLabel(RB.getString("DGenerateCertificate.jlOrganisationUnit.text"));
		GridBagConstraints gbc_jlOrganisationUnit = (GridBagConstraints) gbcLbl.clone();
		gbc_jlOrganisationUnit.gridy = gridy++;

		m_jtfOrganisationUnit = new JTextField(15);
		m_jtfOrganisationUnit.setToolTipText(RB.getString("DGenerateCertificate.m_jtfOrganisationUnit.tooltip"));
		GridBagConstraints gbc_jtfOrganisationUnit = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jtfOrganisationUnit.gridy = gbc_jlOrganisationUnit.gridy;

		// Organisation Name
		JLabel jlOrganisationName = new JLabel(RB.getString("DGenerateCertificate.jlOrganisationName.text"));
		GridBagConstraints gbc_jlOrganisationName = (GridBagConstraints) gbcLbl.clone();
		gbc_jlOrganisationName.gridy = gridy++;

		m_jtfOrganisationName = new JTextField(15);
		m_jtfOrganisationName.setToolTipText(RB.getString("DGenerateCertificate.m_jtfOrganisationName.tooltip"));
		GridBagConstraints gbc_jtfOrganisationName = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jtfOrganisationName.gridy = gbc_jlOrganisationName.gridy;

		// Locality Name
		JLabel jlLocalityName = new JLabel(RB.getString("DGenerateCertificate.jlLocalityName.text"));
		GridBagConstraints gbc_jlLocalityName = (GridBagConstraints) gbcLbl.clone();
		gbc_jlLocalityName.gridy = gridy++;

		m_jtfLocalityName = new JTextField(15);
		m_jtfLocalityName.setToolTipText(RB.getString("DGenerateCertificate.m_jtfLocalityName.tooltip"));
		GridBagConstraints gbc_jtfLocalityName = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jtfLocalityName.gridy = gbc_jlLocalityName.gridy;

		// State Name
		JLabel jlStateName = new JLabel(RB.getString("DGenerateCertificate.jlStateName.text"));
		GridBagConstraints gbc_jlStateName = (GridBagConstraints) gbcLbl.clone();
		gbc_jlStateName.gridy = gridy++;

		m_jtfStateName = new JTextField(15);
		m_jtfStateName.setToolTipText(RB.getString("DGenerateCertificate.m_jtfStateName.tooltip"));
		GridBagConstraints gbc_jtfStateName = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jtfStateName.gridy = gbc_jlStateName.gridy;

		// Country Code
		JLabel jlCountryCode = new JLabel(RB.getString("DGenerateCertificate.jlCountryCode.text"));
		GridBagConstraints gbc_jlCountryCode = (GridBagConstraints) gbcLbl.clone();
		gbc_jlCountryCode.gridy = gridy++;

		m_jtfCountryCode = new JTextField(Locale.getDefault().getCountry(), COUNTRY_CODE_LENGTH);
		doc = m_jtfCountryCode.getDocument();
		if (doc instanceof AbstractDocument)
		{
			((AbstractDocument) doc).setDocumentFilter(new DocumentMaxLengthFilter(
			    m_jtfCountryCode.getColumns()));
		}
		m_jtfCountryCode.setToolTipText(RB.getString("DGenerateCertificate.m_jtfCountryCode.tooltip"));
		GridBagConstraints gbc_jtfCountryCode = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jtfCountryCode.gridy = gbc_jlCountryCode.gridy;

		// Email Address
		JLabel jlEmailAddress = new JLabel(RB.getString("DGenerateCertificate.jlEmailAddress.text"));
		GridBagConstraints gbc_jlEmailAddress = (GridBagConstraints) gbcLbl.clone();
		gbc_jlEmailAddress.gridy = gridy++;

		m_jtfEmailAddress = new JTextField(15);
		m_jtfEmailAddress.setToolTipText(RB.getString("DGenerateCertificate.m_jtfEmailAddress.tooltip"));
		GridBagConstraints gbc_jtfEmailAddress = (GridBagConstraints) gbcEdCtrl.clone();
		gbc_jtfEmailAddress.gridy = gbc_jlEmailAddress.gridy;

		// Put it all together
		JPanel jpOptions = new JPanel(new GridBagLayout());
		jpOptions.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpOptions.add(jlSigAlg, gbc_jlSigAlg);
		jpOptions.add(m_jcbSigAlg, gbc_jcbSigAlg);
		jpOptions.add(jlValidity, gbc_jlValidity);
		jpOptions.add(m_jtfValidity, gbc_jtfValidity);
		jpOptions.add(jlCommonName, gbc_jlCommonName);
		jpOptions.add(m_jtfCommonName, gbc_jtfCommonName);
		jpOptions.add(jlOrganisationUnit, gbc_jlOrganisationUnit);
		jpOptions.add(m_jtfOrganisationUnit, gbc_jtfOrganisationUnit);
		jpOptions.add(jlOrganisationName, gbc_jlOrganisationName);
		jpOptions.add(m_jtfOrganisationName, gbc_jtfOrganisationName);
		jpOptions.add(jlLocalityName, gbc_jlLocalityName);
		jpOptions.add(m_jtfLocalityName, gbc_jtfLocalityName);
		jpOptions.add(jlStateName, gbc_jlStateName);
		jpOptions.add(m_jtfStateName, gbc_jtfStateName);
		jpOptions.add(jlCountryCode, gbc_jlCountryCode);
		jpOptions.add(m_jtfCountryCode, gbc_jtfCountryCode);
		jpOptions.add(jlEmailAddress, gbc_jlEmailAddress);
		jpOptions.add(m_jtfEmailAddress, gbc_jtfEmailAddress);

		JButton jbOK = new JButton(RB.getString("DGenerateCertificate.jbOK.text"));
		jbOK.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				okPressed();
			}
		});

		JButton jbCancel = new JButton(RB.getString("DGenerateCertificate.jbCancel.text"));
		jbCancel.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				cancelPressed();
			}
		});
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
		    KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction()
		{
			public void actionPerformed(ActionEvent evt)
			{
				cancelPressed();
			}
		});

		JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpButtons.add(jbOK);
		jpButtons.add(jbCancel);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpOptions, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter()
		{
			@Override
			public void windowClosing(WindowEvent evt)
			{
				closeDialog();
			}
		});

		setTitle(sTitle);
		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();

		// Focus common name input by default
		m_jtfCommonName.requestFocusInWindow();
	}

	/**
	 * Populate the signature algorithm combo box with the signature algorithms applicable to the key pair
	 * algorithm. Also set a sane default selected item, and disable the combo box if it has less than 2
	 * items.
	 * 
	 * @param type key pair type
	 * @param combo the combo box to populate
	 */
	private static void populateSigAlgs(KeyPairType type, JComboBox combo)
	{
		combo.removeAllItems();
		for (SignatureType st : SignatureType.valuesFor(type))
		{
			combo.addItem(st);
		}

		combo.setSelectedItem(SignatureType.defaultFor(type));

		combo.setEnabled(combo.getItemCount() > 1);
	}

	/**
	 * Generate a certificate based on the parameters supplied to the dialog and the user entry.
	 * 
	 * @return True if the certificate generation is successful, false otherwise
	 */
	private boolean generateCertificate()
	{
		// Validate dialog's field values

		int iValidity = validateValidity(m_jtfValidity.getText());
		if (iValidity == BAD_VALIDITY)
		{
			SwingHelper.selectAndFocus(m_jtfValidity);
			return false;
		}

		String sCommonName = validateCommonName(m_jtfCommonName.getText());
		String sOrganisationUnit = validateOrganisationUnit(m_jtfOrganisationUnit.getText());
		String sOrganisationName = validateOrganisationName(m_jtfOrganisationName.getText());
		String sLocalityName = validateLocalityName(m_jtfLocalityName.getText());
		String sStateName = validateStateName(m_jtfStateName.getText());
		String sCountryCode = validateCountryCode(m_jtfCountryCode.getText());
		String sEmailAddress = validateEmailAddress(m_jtfEmailAddress.getText());

		if (sCommonName == null && sOrganisationUnit == null && sOrganisationName == null &&
		    sLocalityName == null && sStateName == null && sCountryCode == null && sEmailAddress == null)
		{
			JOptionPane.showMessageDialog(this,
			    RB.getString("DGenerateCertificate.ValueReqCertAttr.message"), getTitle(),
			    JOptionPane.WARNING_MESSAGE);
			return false;
		}

		// Country code must be two characters long
		if (sCountryCode != null && sCountryCode.length() != COUNTRY_CODE_LENGTH)
		{
			JOptionPane.showMessageDialog(this, MessageFormat.format(
			    RB.getString("DGenerateCertificate.CountryCodeLength.message"), COUNTRY_CODE_LENGTH),
			    getTitle(), JOptionPane.WARNING_MESSAGE);
			SwingHelper.selectAndFocus(m_jtfCountryCode);
			return false;
		}

		// Generate certificate...

		try
		{
			SignatureType signatureType = (SignatureType) m_jcbSigAlg.getSelectedItem();
			m_certificate =
			    X509CertUtil.generateCert(sCommonName, sOrganisationUnit, sOrganisationName, sLocalityName,
			        sStateName, sCountryCode, sEmailAddress, iValidity, m_keyPair.getPublic(),
			        m_keyPair.getPrivate(), signatureType);
		}
		catch (CryptoException ex)
		{
			DThrowable dThrowable = new DThrowable(this, null, true, ex);
			dThrowable.setLocationRelativeTo(getParent());
			SwingHelper.showAndWait(dThrowable);
			closeDialog();
		}

		return true;
	}

	/**
	 * Validate the Validity value supplied as a string and convert it to an integer.
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
			JOptionPane.showMessageDialog(this, RB.getString("DGenerateCertificate.ValReqValidity.message"),
			    getTitle(), JOptionPane.WARNING_MESSAGE);
			return BAD_VALIDITY;
		}

		try
		{
			iValidity = Integer.parseInt(sValidity);
		}
		catch (NumberFormatException ex)
		{
			JOptionPane.showMessageDialog(this, RB.getString("DGenerateCertificate.ValidityInteger.message"),
			    getTitle(), JOptionPane.WARNING_MESSAGE);
			return BAD_VALIDITY;
		}

		if (iValidity < 1)
		{
			JOptionPane.showMessageDialog(this, RB.getString("DGenerateCertificate.ValidityNonZero.message"),
			    getTitle(), JOptionPane.WARNING_MESSAGE);
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
	 * @return The generated certificate or null if the user cancelled the dialog
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
