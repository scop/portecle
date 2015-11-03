/*
 * DViewCertificate.java
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
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Set;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
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
 * Modal dialog to display the details of one or more X.509 certificates. The details of one certificate are displayed
 * at a time with selector buttons allowing the movement to another of the certificates.
 */
class DViewCertificate
    extends PortecleJDialog
{
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

	/** SSL/TLS connection protocol text field */
	private JTextField m_jtfProtocol;

	/** SSL/TLS connection cipher suite text field */
	private JTextField m_jtfCipherSuite;

	/** Button used to display the certificate's extensions */
	private JButton m_jbExtensions;

	/** Stores certificate(s) to display */
	private final X509Certificate[] m_certs;

	/** The currently selected certificate */
	private int m_iSelCert;

	/** SSL/TLS connection protocol */
	private final String m_connectionProtocol;

	/** SSL/TLS connection cipher suite */
	private final String m_connectionCipherSuite;

	/**
	 * Creates new DViewCertificate dialog.
	 * 
	 * @param parent Parent window
	 * @param sTitle The dialog title
	 * @param certs Certificate(s) chain to display
	 * @throws CryptoException A problem was encountered getting the certificates' details
	 */
	public DViewCertificate(Window parent, String sTitle, X509Certificate[] certs)
	    throws CryptoException
	{
		this(parent, sTitle, certs, null, null);
	}

	/**
	 * Creates new DViewCertificate dialog.
	 * 
	 * @param parent Parent window
	 * @param sTitle The dialog title
	 * @param certs Certificate(s) chain to display
	 * @param connectionProtocol SSL/TLS connection protocol
	 * @param connectionCipherSuite SSL/TLS connection cipher suite
	 * @throws CryptoException A problem was encountered getting the certificates' details
	 */
	public DViewCertificate(Window parent, String sTitle, X509Certificate[] certs, String connectionProtocol,
	    String connectionCipherSuite)
	        throws CryptoException
	{
		super(parent, sTitle, true);
		m_certs = certs;
		m_connectionProtocol = connectionProtocol;
		m_connectionCipherSuite = connectionCipherSuite;
		initComponents();
	}

	/**
	 * Create, show, and wait for a new DViewCertificate dialog.
	 * 
	 * @param parent Parent window
	 * @param url URL, URI or file to load CRL from
	 */
	public static boolean showAndWait(Window parent, Object url)
	{
		ArrayList<Exception> exs = new ArrayList<>();
		X509Certificate[] certs;

		try
		{
			certs = X509CertUtil.loadCertificates(NetUtil.toURL(url), exs);

			if (certs == null)
			{
				// None of the types worked - show each of the errors?
				int iSelected = SwingHelper.showConfirmDialog(parent,
				    MessageFormat.format(RB.getString("FPortecle.NoOpenCertificate.message"), url),
				    RB.getString("FPortecle.OpenCertificate.Title"));
				if (iSelected == JOptionPane.YES_OPTION)
				{
					for (Exception e : exs)
					{
						DThrowable.showAndWait(parent, null, e);
					}
				}
				return false;
			}
			else if (certs.length == 0)
			{
				JOptionPane.showMessageDialog(parent,
				    MessageFormat.format(RB.getString("FPortecle.NoCertsFound.message"), url),
				    RB.getString("FPortecle.OpenCertificate.Title"), JOptionPane.WARNING_MESSAGE);
				return false;
			}

			DViewCertificate dialog = new DViewCertificate(parent,
			    MessageFormat.format(RB.getString("FPortecle.CertDetails.Title"), url), certs);
			dialog.setLocationRelativeTo(parent);
			SwingHelper.showAndWait(dialog);
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(parent, null, ex);
			return false;
		}

		return true;
	}

	/**
	 * Initialize the dialog's GUI components.
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
			@Override
			public void actionPerformed(ActionEvent evt)
			{
				leftPressed();
			}
		});
		m_jbLeft.setToolTipText(RB.getString("DViewCertificate.m_jbLeft.tooltip"));
		m_jbLeft.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
		    getClass().getResource(RB.getString("DViewCertificate.m_jbLeft.image")))));

		m_jlSelector = new JLabel();

		m_jbRight = new JButton();
		m_jbRight.setMnemonic(KeyEvent.VK_RIGHT);
		m_jbRight.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent evt)
			{
				rightPressed();
			}
		});
		m_jbRight.setToolTipText(RB.getString("DViewCertificate.m_jbRight.tooltip"));
		m_jbRight.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
		    getClass().getResource(RB.getString("DViewCertificate.m_jbRight.image")))));

		JPanel jpSelector = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpSelector.add(m_jbLeft);
		jpSelector.add(m_jlSelector);
		jpSelector.add(m_jbRight);

		// Certificate details:

		// Grid Bag Constraints templates for labels and text fields of certificate details
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

		int gridy = 0;

		// Version
		JLabel jlVersion = new JLabel(RB.getString("DViewCertificate.jlVersion.text"));
		GridBagConstraints gbc_jlVersion = (GridBagConstraints) gbcLbl.clone();
		gbc_jlVersion.gridy = gridy;

		m_jtfVersion = new JTextField(3);
		m_jtfVersion.setEditable(false);
		m_jtfVersion.setToolTipText(RB.getString("DViewCertificate.m_jtfVersion.tooltip"));
		jlVersion.setLabelFor(m_jtfVersion);
		GridBagConstraints gbc_jtfVersion = (GridBagConstraints) gbcTf.clone();
		gbc_jtfVersion.gridy = gridy++;

		// Subject
		JLabel jlSubject = new JLabel(RB.getString("DViewCertificate.jlSubject.text"));
		GridBagConstraints gbc_jlSubject = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSubject.gridy = gridy;

		m_jtfSubject = new JTextField(36);
		m_jtfSubject.setEditable(false);
		m_jtfSubject.setToolTipText(RB.getString("DViewCertificate.m_jtfSubject.tooltip"));
		jlSubject.setLabelFor(m_jtfSubject);
		GridBagConstraints gbc_jtfSubject = (GridBagConstraints) gbcTf.clone();
		gbc_jtfSubject.gridy = gridy++;

		// Issuer
		JLabel jlIssuer = new JLabel(RB.getString("DViewCertificate.jlIssuer.text"));
		GridBagConstraints gbc_jlIssuer = (GridBagConstraints) gbcLbl.clone();
		gbc_jlIssuer.gridy = gridy;

		m_jtfIssuer = new JTextField(36);
		m_jtfIssuer.setEditable(false);
		m_jtfIssuer.setToolTipText(RB.getString("DViewCertificate.m_jtfIssuer.tooltip"));
		jlIssuer.setLabelFor(m_jtfIssuer);
		GridBagConstraints gbc_jtfIssuer = (GridBagConstraints) gbcTf.clone();
		gbc_jtfIssuer.gridy = gridy++;

		// Serial Number
		JLabel jlSerialNumber = new JLabel(RB.getString("DViewCertificate.jlSerialNumber.text"));
		GridBagConstraints gbc_jlSerialNumber = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSerialNumber.gridy = gridy;

		m_jtfSerialNumber = new JTextField(25);
		m_jtfSerialNumber.setEditable(false);
		m_jtfSerialNumber.setToolTipText(RB.getString("DViewCertificate.m_jtfSerialNumber.tooltip"));
		jlSerialNumber.setLabelFor(m_jtfSerialNumber);
		GridBagConstraints gbc_jtfSerialNumber = (GridBagConstraints) gbcTf.clone();
		gbc_jtfSerialNumber.gridy = gridy++;

		// Valid From
		JLabel jlValidFrom = new JLabel(RB.getString("DViewCertificate.jlValidFrom.text"));
		GridBagConstraints gbc_jlValidFrom = (GridBagConstraints) gbcLbl.clone();
		gbc_jlValidFrom.gridy = gridy;

		m_jtfValidFrom = new JTextField(25);
		m_jtfValidFrom.setEditable(false);
		m_jtfValidFrom.setToolTipText(RB.getString("DViewCertificate.m_jtfValidFrom.tooltip"));
		jlValidFrom.setLabelFor(jlValidFrom);
		GridBagConstraints gbc_jtfValidFrom = (GridBagConstraints) gbcTf.clone();
		gbc_jtfValidFrom.gridy = gridy++;

		// Valid Until
		JLabel jlValidUntil = new JLabel(RB.getString("DViewCertificate.jlValidUntil.text"));
		GridBagConstraints gbc_jlValidUntil = (GridBagConstraints) gbcLbl.clone();
		gbc_jlValidUntil.gridy = gridy;

		m_jtfValidUntil = new JTextField(25);
		m_jtfValidUntil.setEditable(false);
		m_jtfValidUntil.setToolTipText(RB.getString("DViewCertificate.m_jtfValidUntil.tooltip"));
		jlValidUntil.setLabelFor(m_jtfValidUntil);
		GridBagConstraints gbc_jtfValidUntil = (GridBagConstraints) gbcTf.clone();
		gbc_jtfValidUntil.gridy = gridy++;

		// Public Key
		JLabel jlPublicKey = new JLabel(RB.getString("DViewCertificate.jlPublicKey.text"));
		GridBagConstraints gbc_jlPublicKey = (GridBagConstraints) gbcLbl.clone();
		gbc_jlPublicKey.gridy = gridy;

		m_jtfPublicKey = new JTextField(15);
		m_jtfPublicKey.setEditable(false);
		m_jtfPublicKey.setToolTipText(RB.getString("DViewCertificate.m_jtfPublicKey.tooltip"));
		jlPublicKey.setLabelFor(m_jtfPublicKey);
		GridBagConstraints gbc_jtfPublicKey = (GridBagConstraints) gbcTf.clone();
		gbc_jtfPublicKey.gridy = gridy++;

		// Signature Algorithm
		JLabel jlSignatureAlgorithm = new JLabel(RB.getString("DViewCertificate.jlSignatureAlgorithm.text"));
		GridBagConstraints gbc_jlSignatureAlgorithm = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSignatureAlgorithm.gridy = gridy;

		m_jtfSignatureAlgorithm = new JTextField(15);
		m_jtfSignatureAlgorithm.setEditable(false);
		m_jtfSignatureAlgorithm.setToolTipText(RB.getString("DViewCertificate.m_jtfSignatureAlgorithm.tooltip"));
		jlSignatureAlgorithm.setLabelFor(m_jtfSignatureAlgorithm);
		GridBagConstraints gbc_jtfSignatureAlgorithm = (GridBagConstraints) gbcTf.clone();
		gbc_jtfSignatureAlgorithm.gridy = gridy++;

		// SHA-1 Fingerprint
		JLabel jlSHA1Fingerprint = new JLabel(RB.getString("DViewCertificate.jlSHA1Fingerprint.text"));
		GridBagConstraints gbc_jlSHA1Fingerprint = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSHA1Fingerprint.gridy = gridy;

		m_jtfSHA1Fingerprint = new JTextField(36);
		m_jtfSHA1Fingerprint.setEditable(false);
		m_jtfSHA1Fingerprint.setToolTipText(RB.getString("DViewCertificate.m_jtfSHA1Fingerprint.tooltip"));
		jlSHA1Fingerprint.setLabelFor(m_jtfSHA1Fingerprint);
		GridBagConstraints gbc_jtfSHA1Fingerprint = (GridBagConstraints) gbcTf.clone();
		gbc_jtfSHA1Fingerprint.gridy = gridy++;

		// MD5 Fingerprint
		JLabel jlMD5Fingerprint = new JLabel(RB.getString("DViewCertificate.jlMD5Fingerprint.text"));
		GridBagConstraints gbc_jlMD5Fingerprint = (GridBagConstraints) gbcLbl.clone();
		gbc_jlMD5Fingerprint.gridy = gridy;

		m_jtfMD5Fingerprint = new JTextField(36);
		m_jtfMD5Fingerprint.setEditable(false);
		m_jtfMD5Fingerprint.setToolTipText(RB.getString("DViewCertificate.m_jtfMD5Fingerprint.tooltip"));
		jlMD5Fingerprint.setLabelFor(m_jtfMD5Fingerprint);
		GridBagConstraints gbc_jtfMD5Fingerprint = (GridBagConstraints) gbcTf.clone();
		gbc_jtfMD5Fingerprint.gridy = gridy++;

		// Extensions
		m_jbExtensions = new JButton(RB.getString("DViewCertificate.m_jbExtensions.text"));

		m_jbExtensions.setMnemonic(RB.getString("DViewCertificate.m_jbExtensions.mnemonic").charAt(0));
		m_jbExtensions.setToolTipText(RB.getString("DViewCertificate.m_jbExtensions.tooltip"));
		m_jbExtensions.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent evt)
			{
				extensionsPressed();
			}
		});

		// PEM Encoding
		JButton jbPemEncoding = new JButton(RB.getString("DViewCertificate.jbPemEncoding.text"));

		jbPemEncoding.setMnemonic(RB.getString("DViewCertificate.jbPemEncoding.mnemonic").charAt(0));
		jbPemEncoding.setToolTipText(RB.getString("DViewCertificate.jbPemEncoding.tooltip"));
		jbPemEncoding.addActionListener(new ActionListener()
		{
			@Override
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
		gbc_jpButtons.gridy = gridy++;
		gbc_jpButtons.gridwidth = 2;
		gbc_jpButtons.gridheight = 1;
		gbc_jpButtons.insets = new Insets(5, 5, 5, 5);
		gbc_jpButtons.anchor = GridBagConstraints.EAST;

		// SSL/TLS connection protocol
		JLabel jlProtocol = new JLabel(RB.getString("DViewCertificate.jlProtocol.text"));
		GridBagConstraints gbc_jlProtocol = (GridBagConstraints) gbcLbl.clone();
		gbc_jlProtocol.gridy = gridy;

		m_jtfProtocol = new JTextField(36);
		m_jtfProtocol.setEditable(false);
		m_jtfProtocol.setToolTipText(RB.getString("DViewCertificate.m_jtfProtocol.tooltip"));
		jlProtocol.setLabelFor(m_jtfProtocol);
		GridBagConstraints gbc_jtfProtocol = (GridBagConstraints) gbcTf.clone();
		gbc_jtfProtocol.gridy = gridy++;

		// SSL/TLS connection cipher suite
		JLabel jlCipherSuite = new JLabel(RB.getString("DViewCertificate.jlCipherSuite.text"));
		GridBagConstraints gbc_jlCipherSuite = (GridBagConstraints) gbcLbl.clone();
		gbc_jlCipherSuite.gridy = gridy;

		m_jtfCipherSuite = new JTextField(36);
		m_jtfCipherSuite.setEditable(false);
		m_jtfCipherSuite.setToolTipText(RB.getString("DViewCertificate.m_jtfCipherSuite.tooltip"));
		jlCipherSuite.setLabelFor(m_jtfCipherSuite);
		GridBagConstraints gbc_jtfCipherSuite = (GridBagConstraints) gbcTf.clone();
		gbc_jtfCipherSuite.gridy = gridy++;

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
		if (m_connectionProtocol != null)
		{
			jpCertificate.add(jlProtocol, gbc_jlProtocol);
			jpCertificate.add(m_jtfProtocol, gbc_jtfProtocol);
		}
		if (m_connectionCipherSuite != null)
		{
			jpCertificate.add(jlCipherSuite, gbc_jlCipherSuite);
			jpCertificate.add(m_jtfCipherSuite, gbc_jtfCipherSuite);
		}

		// Populate the dialog with the first certificate (if any)
		populateDialog();

		// OK button
		JPanel jpOK = new JPanel(new FlowLayout(FlowLayout.CENTER));
		JButton jbOK = getOkButton(true);
		jpOK.add(jbOK);

		// Put it all together
		getContentPane().add(jpSelector, BorderLayout.NORTH);
		getContentPane().add(jpCertificate, BorderLayout.CENTER);
		getContentPane().add(jpOK, BorderLayout.SOUTH);

		getRootPane().setDefaultButton(jbOK);

		initDialog();

		jbOK.requestFocusInWindow();
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
			m_jlSelector.setText(MessageFormat.format(RB.getString("DViewCertificate.m_jlSelector.text"), 0, 0));
			return;
		}

		// Set selection label and buttons
		m_jlSelector.setText(
		    MessageFormat.format(RB.getString("DViewCertificate.m_jlSelector.text"), m_iSelCert + 1, m_certs.length));

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
		m_jtfSerialNumber.setText(StringUtil.toHex(cert.getSerialNumber(), 4, " ").toString());
		m_jtfSerialNumber.setCaretPosition(0);

		// Valid From (include timezone)
		m_jtfValidFrom.setText(DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.LONG).format(startDate));

		if (bNotYetValid)
		{
			m_jtfValidFrom.setText(MessageFormat.format(
			    RB.getString("DViewCertificate.m_jtfValidFrom.notyetvalid.text"), m_jtfValidFrom.getText()));
			m_jtfValidFrom.setForeground(Color.red);
		}
		else
		{
			m_jtfValidFrom.setForeground(m_jtfVersion.getForeground());
		}
		m_jtfValidFrom.setCaretPosition(0);

		// Valid Until (include time zone)
		m_jtfValidUntil.setText(DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.LONG).format(endDate));

		if (bNoLongerValid)
		{
			m_jtfValidUntil.setText(MessageFormat.format(RB.getString("DViewCertificate.m_jtfValidUntil.expired.text"),
			    m_jtfValidUntil.getText()));
			m_jtfValidUntil.setForeground(Color.red);
		}
		else
		{
			m_jtfValidUntil.setForeground(m_jtfVersion.getForeground());
		}
		m_jtfValidUntil.setCaretPosition(0);

		// Public Key (algorithm and key size)
		int iKeySize = KeyPairUtil.getKeyLength(cert.getPublicKey());
		m_jtfPublicKey.setText(cert.getPublicKey().getAlgorithm());

		if (iKeySize != KeyPairUtil.UNKNOWN_KEY_SIZE)
		{
			m_jtfPublicKey.setText(MessageFormat.format(RB.getString("DViewCertificate.m_jtfPublicKey.text"),
			    m_jtfPublicKey.getText(), iKeySize));
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
			throw new CryptoException(RB.getString("DViewCertificate.NoGetEncodedCert.exception.message"), ex);
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

		// SSL/TLS connection details
		m_jtfProtocol.setText(m_connectionProtocol);
		m_jtfProtocol.setCaretPosition(0);
		m_jtfCipherSuite.setText(m_connectionCipherSuite);
		m_jtfCipherSuite.setCaretPosition(0);
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
	 * Extensions button pressed or otherwise activated. Show the extensions of the currently selected certificate.
	 */
	private void extensionsPressed()
	{
		if (m_iSelCert == -1 || m_iSelCert >= m_certs.length)
		{
			return;
		}

		X509Certificate cert = m_certs[m_iSelCert];

		DViewExtensions dViewExtensions = new DViewExtensions(this,
		    MessageFormat.format(RB.getString("DViewCertificate.Extensions.Title"), m_iSelCert + 1, m_certs.length),
		    true, cert);
		dViewExtensions.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dViewExtensions);
	}

	/**
	 * PEM Encoding Encoding button pressed or otherwise activated. Show the PEM encoding for the currently selected
	 * certificate.
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
		chooser.setDialogTitle(RB.getString("DViewCertificate.Save.Title"));
		chooser.setMultiSelectionEnabled(false);

		try
		{
			DViewPEM dViewCertPem =
			    new DViewPEM(this, MessageFormat.format(RB.getString("DViewCertificate.PemEncoding.Title"),
			        m_iSelCert + 1, m_certs.length), cert, chooser);
			dViewCertPem.setLocationRelativeTo(this);
			SwingHelper.showAndWait(dViewCertPem);
		}
		catch (CryptoException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return;
		}
	}
}
