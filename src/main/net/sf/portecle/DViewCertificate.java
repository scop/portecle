/*
 * DViewCertificate.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004-2005 Ville Skyttä, ville.skytta@iki.fi
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

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.MessageFormat;
import java.util.Date;
import java.util.ResourceBundle;
import java.util.Set;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import net.sf.portecle.crypto.CryptoException;
import net.sf.portecle.crypto.DigestType;
import net.sf.portecle.crypto.DigestUtil;
import net.sf.portecle.crypto.KeyPairUtil;
import net.sf.portecle.crypto.SignatureType;
import net.sf.portecle.crypto.X509CertUtil;
import net.sf.portecle.gui.SwingHelper;
import net.sf.portecle.gui.crypto.DViewPEM;
import net.sf.portecle.gui.error.DThrowable;

/**
 * Displays the details of one or more X.509 certificates. The details of one certificate are displayed at a
 * time with selector buttons allowing the movement to another of the certificates.
 */
class DViewCertificate
    extends JDialog
{
	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

	/** Move left selector button */
	private JButton m_jbLeft;

	/** Move right selector button */
	private JButton m_jbRight;

	/** Selection status label */
	private JLabel m_jlSelector;

	/** Certificate version text field */
	private JTextField m_jtfVersion;

	/** Certificate Subject text field */
	private JTextField m_jtfSubject;

	/** Certificate Issuer text field */
	private JTextField m_jtfIssuer;

	/** Certificate Serial Number text field */
	private JTextField m_jtfSerialNumber;

	/** Certificate Valid From text field */
	private JTextField m_jtfValidFrom;

	/** Certificate Valid Until text field */
	private JTextField m_jtfValidUntil;

	/** Certificate Public Key text field */
	private JTextField m_jtfPublicKey;

	/** Certificate Signature Algorithm text field */
	private JTextField m_jtfSignatureAlgorithm;

	/** Certificate MD5 Fingerprint text field */
	private JTextField m_jtfMD5Fingerprint;

	/** Certificate SHA-1 Fingerprint text field */
	private JTextField m_jtfSHA1Fingerprint;

	/** Button used to display the certificate's extensions */
	private JButton m_jbExtensions;

	/** Stores certificate(s) to display */
	private X509Certificate[] m_certs;

	/** The currently selected certificate */
	private int m_iSelCert;

	/**
	 * Creates new DViewCertificate dialog where the parent is a frame.
	 * 
	 * @param parent Parent frame
	 * @param sTitle The dialog title
	 * @param bModal Is dialog modal?
	 * @param certs Certificate(s) chain to display
	 * @throws CryptoException A problem was encountered getting the certificates' details
	 */
	public DViewCertificate(JFrame parent, String sTitle, boolean bModal, X509Certificate[] certs)
	    throws CryptoException
	{
		super(parent, sTitle, bModal);
		m_certs = certs;
		initComponents();
	}

	/**
	 * Creates new DViewCertificate dialog where the parent is a dialog.
	 * 
	 * @param parent Parent dialog
	 * @param sTitle The dialog title
	 * @param bModal Is dialog modal?
	 * @param certs Certificate(s) to display
	 * @throws CryptoException A problem was encountered getting the certificates' details
	 */
	public DViewCertificate(JDialog parent, String sTitle, boolean bModal, X509Certificate[] certs)
	    throws CryptoException
	{
		super(parent, sTitle, bModal);
		m_certs = certs;
		initComponents();
	}

	/**
	 * Initialise the dialog's GUI components.
	 * 
	 * @throws CryptoException A problem was encountered getting the certificates' details
	 */
	private void initComponents()
	    throws CryptoException
	{
		// Are there any certificates to view?
		if (m_certs.length == 0)
		{
			m_iSelCert = -1;
		}
		else
		{
			m_iSelCert = 0;
		}

		// Selector
		m_jbLeft = new JButton();
		m_jbLeft.setMnemonic(KeyEvent.VK_LEFT);
		m_jbLeft.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				leftPressed();
			}
		});
		m_jbLeft.setToolTipText(m_res.getString("DViewCertificate.m_jbLeft.tooltip"));
		m_jbLeft.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
		    getClass().getResource(m_res.getString("DViewCertificate.m_jbLeft.image")))));

		m_jlSelector = new JLabel("");

		m_jbRight = new JButton();
		m_jbRight.setMnemonic(KeyEvent.VK_RIGHT);
		m_jbRight.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				rightPressed();
			}
		});
		m_jbRight.setToolTipText(m_res.getString("DViewCertificate.m_jbRight.tooltip"));
		m_jbRight.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
		    getClass().getResource(m_res.getString("DViewCertificate.m_jbRight.image")))));

		JPanel jpSelector = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpSelector.add(m_jbLeft);
		jpSelector.add(m_jlSelector);
		jpSelector.add(m_jbRight);

		// Certificate details:

		// Grid Bag Constraints templates for labels and text fields
		// of certificate details
		GridBagConstraints gbcLbl = new GridBagConstraints();
		gbcLbl.gridx = 0;
		gbcLbl.gridwidth = 1;
		gbcLbl.gridheight = 1;
		gbcLbl.insets = new Insets(5, 5, 5, 5);
		gbcLbl.anchor = GridBagConstraints.EAST;

		GridBagConstraints gbcTf = new GridBagConstraints();
		gbcTf.gridx = 1;
		gbcTf.gridwidth = 1;
		gbcTf.gridheight = 1;
		gbcTf.insets = new Insets(5, 5, 5, 5);
		gbcTf.anchor = GridBagConstraints.WEST;

		// Version
		JLabel jlVersion = new JLabel(m_res.getString("DViewCertificate.jlVersion.text"));
		GridBagConstraints gbc_jlVersion = (GridBagConstraints) gbcLbl.clone();
		gbc_jlVersion.gridy = 0;

		m_jtfVersion = new JTextField(3);
		m_jtfVersion.setEditable(false);
		m_jtfVersion.setToolTipText(m_res.getString("DViewCertificate.m_jtfVersion.tooltip"));
		GridBagConstraints gbc_jtfVersion = (GridBagConstraints) gbcTf.clone();
		gbc_jtfVersion.gridy = 0;

		// Subject
		JLabel jlSubject = new JLabel(m_res.getString("DViewCertificate.jlSubject.text"));
		GridBagConstraints gbc_jlSubject = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSubject.gridy = 1;

		m_jtfSubject = new JTextField(36);
		m_jtfSubject.setEditable(false);
		m_jtfSubject.setToolTipText(m_res.getString("DViewCertificate.m_jtfSubject.tooltip"));
		GridBagConstraints gbc_jtfSubject = (GridBagConstraints) gbcTf.clone();
		gbc_jtfSubject.gridy = 1;

		// Issuer
		JLabel jlIssuer = new JLabel(m_res.getString("DViewCertificate.jlIssuer.text"));
		GridBagConstraints gbc_jlIssuer = (GridBagConstraints) gbcLbl.clone();
		gbc_jlIssuer.gridy = 2;

		m_jtfIssuer = new JTextField(36);
		m_jtfIssuer.setEditable(false);
		m_jtfIssuer.setToolTipText(m_res.getString("DViewCertificate.m_jtfIssuer.tooltip"));
		GridBagConstraints gbc_jtfIssuer = (GridBagConstraints) gbcTf.clone();
		gbc_jtfIssuer.gridy = 2;

		// Serial Number
		JLabel jlSerialNumber = new JLabel(m_res.getString("DViewCertificate.jlSerialNumber.text"));
		GridBagConstraints gbc_jlSerialNumber = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSerialNumber.gridy = 3;

		m_jtfSerialNumber = new JTextField(25);
		m_jtfSerialNumber.setEditable(false);
		m_jtfSerialNumber.setToolTipText(m_res.getString("DViewCertificate.m_jtfSerialNumber.tooltip"));
		GridBagConstraints gbc_jtfSerialNumber = (GridBagConstraints) gbcTf.clone();
		gbc_jtfSerialNumber.gridy = 3;

		// Valid From
		JLabel jlValidFrom = new JLabel(m_res.getString("DViewCertificate.jlValidFrom.text"));
		GridBagConstraints gbc_jlValidFrom = (GridBagConstraints) gbcLbl.clone();
		gbc_jlValidFrom.gridy = 4;

		m_jtfValidFrom = new JTextField(25);
		m_jtfValidFrom.setEditable(false);
		m_jtfValidFrom.setToolTipText(m_res.getString("DViewCertificate.m_jtfValidFrom.tooltip"));
		GridBagConstraints gbc_jtfValidFrom = (GridBagConstraints) gbcTf.clone();
		gbc_jtfValidFrom.gridy = 4;

		// Valid Until
		JLabel jlValidUntil = new JLabel(m_res.getString("DViewCertificate.jlValidUntil.text"));
		GridBagConstraints gbc_jlValidUntil = (GridBagConstraints) gbcLbl.clone();
		gbc_jlValidUntil.gridy = 5;

		m_jtfValidUntil = new JTextField(25);
		m_jtfValidUntil.setEditable(false);
		m_jtfValidUntil.setToolTipText(m_res.getString("DViewCertificate.m_jtfValidUntil.tooltip"));
		GridBagConstraints gbc_jtfValidUntil = (GridBagConstraints) gbcTf.clone();
		gbc_jtfValidUntil.gridy = 5;

		// Public Key
		JLabel jlPublicKey = new JLabel(m_res.getString("DViewCertificate.jlPublicKey.text"));
		GridBagConstraints gbc_jlPublicKey = (GridBagConstraints) gbcLbl.clone();
		gbc_jlPublicKey.gridy = 6;

		m_jtfPublicKey = new JTextField(15);
		m_jtfPublicKey.setEditable(false);
		m_jtfPublicKey.setToolTipText(m_res.getString("DViewCertificate.m_jtfPublicKey.tooltip"));
		GridBagConstraints gbc_jtfPublicKey = (GridBagConstraints) gbcTf.clone();
		gbc_jtfPublicKey.gridy = 6;

		// Signature Algorithm
		JLabel jlSignatureAlgorithm =
		    new JLabel(m_res.getString("DViewCertificate.jlSignatureAlgorithm.text"));
		GridBagConstraints gbc_jlSignatureAlgorithm = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSignatureAlgorithm.gridy = 7;

		m_jtfSignatureAlgorithm = new JTextField(15);
		m_jtfSignatureAlgorithm.setEditable(false);
		m_jtfSignatureAlgorithm.setToolTipText(m_res.getString("DViewCertificate.m_jtfSignatureAlgorithm.tooltip"));
		GridBagConstraints gbc_jtfSignatureAlgorithm = (GridBagConstraints) gbcTf.clone();
		gbc_jtfSignatureAlgorithm.gridy = 7;

		// MD5 Fingerprint
		JLabel jlMD5Fingerprint = new JLabel(m_res.getString("DViewCertificate.jlMD5Fingerprint.text"));
		GridBagConstraints gbc_jlMD5Fingerprint = (GridBagConstraints) gbcLbl.clone();
		gbc_jlMD5Fingerprint.gridy = 8;

		m_jtfMD5Fingerprint = new JTextField(36);
		m_jtfMD5Fingerprint.setEditable(false);
		m_jtfMD5Fingerprint.setToolTipText(m_res.getString("DViewCertificate.m_jtfMD5Fingerprint.tooltip"));
		GridBagConstraints gbc_jtfMD5Fingerprint = (GridBagConstraints) gbcTf.clone();
		gbc_jtfMD5Fingerprint.gridy = 8;

		// SHA-1 Fingerprint
		JLabel jlSHA1Fingerprint = new JLabel(m_res.getString("DViewCertificate.jlSHA1Fingerprint.text"));
		GridBagConstraints gbc_jlSHA1Fingerprint = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSHA1Fingerprint.gridy = 9;

		m_jtfSHA1Fingerprint = new JTextField(36);
		m_jtfSHA1Fingerprint.setEditable(false);
		m_jtfSHA1Fingerprint.setToolTipText(m_res.getString("DViewCertificate.m_jtfSHA1Fingerprint.tooltip"));
		GridBagConstraints gbc_jtfSHA1Fingerprint = (GridBagConstraints) gbcTf.clone();
		gbc_jtfSHA1Fingerprint.gridy = 9;

		// Extensions
		m_jbExtensions = new JButton(m_res.getString("DViewCertificate.m_jbExtensions.text"));

		m_jbExtensions.setMnemonic(m_res.getString("DViewCertificate.m_jbExtensions.mnemonic").charAt(0));
		m_jbExtensions.setToolTipText(m_res.getString("DViewCertificate.m_jbExtensions.tooltip"));
		m_jbExtensions.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				extensionsPressed();
			}
		});

		// PEM Encoding
		JButton jbPemEncoding = new JButton(m_res.getString("DViewCertificate.jbPemEncoding.text"));

		jbPemEncoding.setMnemonic(m_res.getString("DViewCertificate.jbPemEncoding.mnemonic").charAt(0));
		jbPemEncoding.setToolTipText(m_res.getString("DViewCertificate.jbPemEncoding.tooltip"));
		jbPemEncoding.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				pemEncodingPressed();
			}
		});

		if (m_certs.length == 0)
		{
			jbPemEncoding.setEnabled(false);
		}

		JPanel jpButtons = new JPanel();
		jpButtons.add(m_jbExtensions);
		jpButtons.add(jbPemEncoding);

		GridBagConstraints gbc_jpButtons = new GridBagConstraints();
		gbc_jpButtons.gridx = 0;
		gbc_jpButtons.gridy = 10;
		gbc_jpButtons.gridwidth = 2;
		gbc_jpButtons.gridheight = 1;
		gbc_jpButtons.insets = new Insets(5, 5, 5, 5);
		gbc_jpButtons.anchor = GridBagConstraints.EAST;

		JPanel jpCertificate = new JPanel(new GridBagLayout());
		jpCertificate.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpCertificate.add(jlVersion, gbc_jlVersion);
		jpCertificate.add(m_jtfVersion, gbc_jtfVersion);
		jpCertificate.add(jlSubject, gbc_jlSubject);
		jpCertificate.add(m_jtfSubject, gbc_jtfSubject);
		jpCertificate.add(jlIssuer, gbc_jlIssuer);
		jpCertificate.add(m_jtfIssuer, gbc_jtfIssuer);
		jpCertificate.add(jlSerialNumber, gbc_jlSerialNumber);
		jpCertificate.add(m_jtfSerialNumber, gbc_jtfSerialNumber);
		jpCertificate.add(jlValidFrom, gbc_jlValidFrom);
		jpCertificate.add(m_jtfValidFrom, gbc_jtfValidFrom);
		jpCertificate.add(jlValidUntil, gbc_jlValidUntil);
		jpCertificate.add(m_jtfValidUntil, gbc_jtfValidUntil);
		jpCertificate.add(jlPublicKey, gbc_jlPublicKey);
		jpCertificate.add(m_jtfPublicKey, gbc_jtfPublicKey);
		jpCertificate.add(jlSignatureAlgorithm, gbc_jlSignatureAlgorithm);
		jpCertificate.add(m_jtfSignatureAlgorithm, gbc_jtfSignatureAlgorithm);
		jpCertificate.add(jlMD5Fingerprint, gbc_jlMD5Fingerprint);
		jpCertificate.add(m_jtfMD5Fingerprint, gbc_jtfMD5Fingerprint);
		jpCertificate.add(jlSHA1Fingerprint, gbc_jlSHA1Fingerprint);
		jpCertificate.add(m_jtfSHA1Fingerprint, gbc_jtfSHA1Fingerprint);
		jpCertificate.add(jpButtons, gbc_jpButtons);

		// Populate the dialog with the first certificate (if any)
		populateDialog();

		// OK button
		JPanel jpOK = new JPanel(new FlowLayout(FlowLayout.CENTER));

		final JButton jbOK = new JButton(m_res.getString("DViewCertificate.jbOK.text"));
		jbOK.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				okPressed();
			}
		});

		jpOK.add(jbOK);

		// Put it all together
		getContentPane().add(jpSelector, BorderLayout.NORTH);
		getContentPane().add(jpCertificate, BorderLayout.CENTER);
		getContentPane().add(jpOK, BorderLayout.SOUTH);

		// Annoying, but resizing wreaks havoc here
		setResizable(false);

		addWindowListener(new WindowAdapter()
		{
			@Override
			public void windowClosing(WindowEvent evt)
			{
				closeDialog();
			}
		});

		getRootPane().setDefaultButton(jbOK);

		pack();

		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				jbOK.requestFocus();
			}
		});
	}

	/**
	 * Populate the dialog with the currently selected certificate's details.
	 * 
	 * @throws CryptoException A problem was encountered getting the certificate's details
	 */
	private void populateDialog()
	    throws CryptoException
	{
		// Certificate selected?
		if (m_iSelCert < 0 || m_iSelCert >= m_certs.length)
		{
			m_jbLeft.setEnabled(false);
			m_jbRight.setEnabled(false);
			m_jlSelector.setText(MessageFormat.format(m_res.getString("DViewCertificate.m_jlSelector.text"),
			    0, 0));
			return;
		}

		// Set selection label and buttons
		m_jlSelector.setText(MessageFormat.format(m_res.getString("DViewCertificate.m_jlSelector.text"),
		    m_iSelCert + 1, m_certs.length));

		if (m_iSelCert == 0)
		{
			m_jbLeft.setEnabled(false);
		}
		else
		{
			m_jbLeft.setEnabled(true);
		}

		if ((m_iSelCert + 1) < m_certs.length)
		{
			m_jbRight.setEnabled(true);
		}
		else
		{
			m_jbRight.setEnabled(false);
		}

		// Get the certificate
		X509Certificate cert = m_certs[m_iSelCert];

		// Has the certificate [not yet become valid/expired]
		Date currentDate = new Date();

		Date startDate = cert.getNotBefore();
		Date endDate = cert.getNotAfter();

		boolean bNotYetValid = currentDate.before(startDate);
		boolean bNoLongerValid = currentDate.after(endDate);

		// Populate the fields:

		// Version
		m_jtfVersion.setText(Integer.toString(cert.getVersion()));
		m_jtfVersion.setCaretPosition(0);

		// Subject
		m_jtfSubject.setText(cert.getSubjectDN().toString());
		m_jtfSubject.setCaretPosition(0);

		// Issuer
		m_jtfIssuer.setText(cert.getIssuerDN().toString());
		m_jtfIssuer.setCaretPosition(0);

		// Serial Number
		m_jtfSerialNumber.setText(new BigInteger(1, cert.getSerialNumber().toByteArray()).toString(16).toUpperCase());
		m_jtfSerialNumber.setCaretPosition(0);

		// Valid From (include timezone)
		m_jtfValidFrom.setText(DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.LONG).format(
		    startDate));

		if (bNotYetValid)
		{
			m_jtfValidFrom.setText(MessageFormat.format(
			    m_res.getString("DViewCertificate.m_jtfValidFrom.notyetvalid.text"), m_jtfValidFrom.getText()));
			m_jtfValidFrom.setForeground(Color.red);
		}
		else
		{
			m_jtfValidFrom.setForeground(m_jtfVersion.getForeground());
		}
		m_jtfValidFrom.setCaretPosition(0);

		// Valid Until (include timezone)
		m_jtfValidUntil.setText(DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.LONG).format(
		    endDate));

		if (bNoLongerValid)
		{
			m_jtfValidUntil.setText(MessageFormat.format(
			    m_res.getString("DViewCertificate.m_jtfValidUntil.expired.text"), m_jtfValidUntil.getText()));
			m_jtfValidUntil.setForeground(Color.red);
		}
		else
		{
			m_jtfValidUntil.setForeground(m_jtfVersion.getForeground());
		}
		m_jtfValidUntil.setCaretPosition(0);

		// Public Key (algorithm and keysize)
		int iKeySize = KeyPairUtil.getKeyLength(cert.getPublicKey());
		m_jtfPublicKey.setText(cert.getPublicKey().getAlgorithm());

		if (iKeySize != -1)
		{
			m_jtfPublicKey.setText(MessageFormat.format(
			    m_res.getString("DViewCertificate.m_jtfPublicKey.text"), m_jtfPublicKey.getText(), iKeySize));
		}
		m_jtfPublicKey.setCaretPosition(0);

		// Signature Algorithm
		String sigAlgName = SignatureType.toString(cert.getSigAlgName());
		m_jtfSignatureAlgorithm.setText(sigAlgName);
		m_jtfSignatureAlgorithm.setCaretPosition(0);

		// Fingerprints
		byte[] bCert;
		try
		{
			bCert = cert.getEncoded();
		}
		catch (CertificateEncodingException ex)
		{
			throw new CryptoException(m_res.getString("DViewCertificate.NoGetEncodedCert.exception.message"),
			    ex);
		}

		m_jtfMD5Fingerprint.setText(DigestUtil.getMessageDigest(bCert, DigestType.MD5));
		m_jtfMD5Fingerprint.setCaretPosition(0);
		m_jtfSHA1Fingerprint.setText(DigestUtil.getMessageDigest(bCert, DigestType.SHA1));
		m_jtfSHA1Fingerprint.setCaretPosition(0);

		// Enable/disable extensions button
		Set<String> critExts = cert.getCriticalExtensionOIDs();
		Set<String> nonCritExts = cert.getNonCriticalExtensionOIDs();

		if ((critExts != null && !critExts.isEmpty()) || (nonCritExts != null && !nonCritExts.isEmpty()))
		{
			// Extensions
			m_jbExtensions.setEnabled(true);
		}
		else
		{
			// No extensions
			m_jbExtensions.setEnabled(false);
		}
	}

	/**
	 * Left certificate selection button pressed. Display the previous certificate if appropriate.
	 */
	private void leftPressed()
	{
		if (m_iSelCert > 0)
		{
			m_iSelCert--;

			try
			{
				populateDialog();
			}
			catch (CryptoException ex)
			{
				DThrowable.showAndWait(this, null, ex);
				dispose();
			}
		}

	}

	/**
	 * Right certificate selection button pressed. Display the next certificate if appropriate.
	 */
	private void rightPressed()
	{
		if ((m_iSelCert + 1) < m_certs.length)
		{
			m_iSelCert++;

			try
			{
				populateDialog();
			}
			catch (CryptoException ex)
			{
				DThrowable.showAndWait(this, null, ex);
				dispose();
			}
		}
	}

	/**
	 * Extensions button pressed or otherwise activated. Show the extensions of the currently selected
	 * certificate.
	 */
	private void extensionsPressed()
	{
		if (m_iSelCert == -1 || m_iSelCert >= m_certs.length)
		{
			return;
		}

		X509Certificate cert = m_certs[m_iSelCert];

		DViewExtensions dViewExtensions =
		    new DViewExtensions(this, MessageFormat.format(
		        m_res.getString("DViewCertificate.Extensions.Title"), m_iSelCert + 1, m_certs.length), true,
		        cert);
		dViewExtensions.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dViewExtensions);
	}

	/**
	 * PEM Encoding Encoding button pressed or otherwise activated. Show the PEM encoding for the currently
	 * selected certificate.
	 */
	private void pemEncodingPressed()
	{
		if (m_iSelCert == -1 || m_iSelCert >= m_certs.length)
		{
			return;
		}

		X509Certificate cert = m_certs[m_iSelCert];

		JFileChooser chooser = FileChooserFactory.getPEMFileChooser(X509CertUtil.getCertificateAlias(cert));
		// TODO: lastdir
		chooser.setDialogTitle(m_res.getString("DViewCertificate.Save.Title"));
		chooser.setMultiSelectionEnabled(false);

		try
		{
			DViewPEM dViewCertPem =
			    new DViewPEM(this, MessageFormat.format(
			        m_res.getString("DViewCertificate.PemEncoding.Title"), m_iSelCert + 1, m_certs.length),
			        true, cert, chooser);
			dViewCertPem.setLocationRelativeTo(this);
			SwingHelper.showAndWait(dViewCertPem);
		}
		catch (CryptoException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return;
		}
	}

	/**
	 * OK button pressed or otherwise activated.
	 */
	private void okPressed()
	{
		closeDialog();
	}

	/**
	 * Hides the View Certificate dialog.
	 */
	private void closeDialog()
	{
		setVisible(false);
		dispose();
	}
}
