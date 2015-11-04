/*
 * DViewCSR.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2006-2014 Ville Skyttä, ville.skytta@iki.fi
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
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.text.MessageFormat;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import net.sf.portecle.crypto.AlgorithmType;
import net.sf.portecle.crypto.CryptoException;
import net.sf.portecle.crypto.KeyPairUtil;
import net.sf.portecle.crypto.NameUtil;
import net.sf.portecle.crypto.SignatureType;
import net.sf.portecle.gui.SwingHelper;
import net.sf.portecle.gui.crypto.DViewPEM;
import net.sf.portecle.gui.error.DThrowable;

/**
 * Modal dialog to display the details of a certification request.
 */
class DViewCSR
    extends PortecleJDialog
{
	/** Version text field */
	private JTextField m_jtfVersion;

	/** Subject text field */
	private JTextField m_jtfSubject;

	/** Certificate Public Key text field */
	private JTextField m_jtfPublicKey;

	/** Certificate Signature Algorithm text field */
	private JTextField m_jtfSignatureAlgorithm;

	/** Stores request to display */
	private final PKCS10CertificationRequest m_req;

	/** Default filename for saving */
	private String m_basename;

	/**
	 * Creates new DViewCSR dialog.
	 * 
	 * @param parent Parent window
	 * @param sTitle The dialog title
	 * @param req Certification request to display
	 * @throws CryptoException A problem was encountered getting the certification request details
	 */
	public DViewCSR(Window parent, String sTitle, PKCS10CertificationRequest req)
	    throws CryptoException
	{
		super(parent, sTitle, true);
		m_req = req;
		initComponents();
	}

	/**
	 * Initialize the dialog's GUI components.
	 * 
	 * @throws CryptoException A problem was encountered getting the request details
	 */
	private void initComponents()
	    throws CryptoException
	{
		// Grid Bag Constraints templates for labels and text fields of CSR details
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
		JLabel jlVersion = new JLabel(RB.getString("DViewCSR.jlVersion.text"));
		GridBagConstraints gbc_jlVersion = (GridBagConstraints) gbcLbl.clone();
		gbc_jlVersion.gridy = 0;

		m_jtfVersion = new JTextField(3);
		m_jtfVersion.setEditable(false);
		m_jtfVersion.setToolTipText(RB.getString("DViewCSR.m_jtfVersion.tooltip"));
		jlVersion.setLabelFor(m_jtfVersion);
		GridBagConstraints gbc_jtfVersion = (GridBagConstraints) gbcTf.clone();
		gbc_jtfVersion.gridy = 0;

		// Subject
		JLabel jlSubject = new JLabel(RB.getString("DViewCSR.jlSubject.text"));
		GridBagConstraints gbc_jlSubject = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSubject.gridy = 1;

		m_jtfSubject = new JTextField(36);
		m_jtfSubject.setEditable(false);
		m_jtfSubject.setToolTipText(RB.getString("DViewCSR.m_jtfSubject.tooltip"));
		jlSubject.setLabelFor(m_jtfSubject);
		GridBagConstraints gbc_jtfSubject = (GridBagConstraints) gbcTf.clone();
		gbc_jtfSubject.gridy = 1;

		// Public Key
		JLabel jlPublicKey = new JLabel(RB.getString("DViewCSR.jlPublicKey.text"));
		GridBagConstraints gbc_jlPublicKey = (GridBagConstraints) gbcLbl.clone();
		gbc_jlPublicKey.gridy = 6;

		m_jtfPublicKey = new JTextField(15);
		m_jtfPublicKey.setEditable(false);
		m_jtfPublicKey.setToolTipText(RB.getString("DViewCSR.m_jtfPublicKey.tooltip"));
		jlPublicKey.setLabelFor(m_jtfPublicKey);
		GridBagConstraints gbc_jtfPublicKey = (GridBagConstraints) gbcTf.clone();
		gbc_jtfPublicKey.gridy = 6;

		// Signature Algorithm
		JLabel jlSignatureAlgorithm = new JLabel(RB.getString("DViewCSR.jlSignatureAlgorithm.text"));
		GridBagConstraints gbc_jlSignatureAlgorithm = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSignatureAlgorithm.gridy = 7;

		m_jtfSignatureAlgorithm = new JTextField(15);
		m_jtfSignatureAlgorithm.setEditable(false);
		m_jtfSignatureAlgorithm.setToolTipText(RB.getString("DViewCSR.m_jtfSignatureAlgorithm.tooltip"));
		jlSignatureAlgorithm.setLabelFor(m_jtfSignatureAlgorithm);
		GridBagConstraints gbc_jtfSignatureAlgorithm = (GridBagConstraints) gbcTf.clone();
		gbc_jtfSignatureAlgorithm.gridy = 7;

		// TODO: attributes, requested extensions

		// PEM Encoding
		JButton jbPemEncoding = new JButton(RB.getString("DViewCSR.jbPemEncoding.text"));
		jbPemEncoding.setMnemonic(RB.getString("DViewCSR.jbPemEncoding.mnemonic").charAt(0));
		jbPemEncoding.setToolTipText(RB.getString("DViewCSR.jbPemEncoding.tooltip"));
		jbPemEncoding.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent evt)
			{
				pemEncodingPressed();
			}
		});
		JPanel jpButtons = new JPanel();
		jpButtons.add(jbPemEncoding);

		GridBagConstraints gbc_jpButtons = new GridBagConstraints();
		gbc_jpButtons.gridx = 0;
		gbc_jpButtons.gridy = 10;
		gbc_jpButtons.gridwidth = 2;
		gbc_jpButtons.gridheight = 1;
		gbc_jpButtons.insets = new Insets(5, 5, 5, 5);
		gbc_jpButtons.anchor = GridBagConstraints.EAST;

		JPanel jpCSR = new JPanel(new GridBagLayout());
		jpCSR.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpCSR.add(jlVersion, gbc_jlVersion);
		jpCSR.add(m_jtfVersion, gbc_jtfVersion);
		jpCSR.add(jlSubject, gbc_jlSubject);
		jpCSR.add(m_jtfSubject, gbc_jtfSubject);
		jpCSR.add(jlPublicKey, gbc_jlPublicKey);
		jpCSR.add(m_jtfPublicKey, gbc_jtfPublicKey);
		jpCSR.add(jlSignatureAlgorithm, gbc_jlSignatureAlgorithm);
		jpCSR.add(m_jtfSignatureAlgorithm, gbc_jtfSignatureAlgorithm);
		jpCSR.add(jpButtons, gbc_jpButtons);

		// Populate the dialog with the first certificate (if any)
		populateDialog();

		// OK button
		JPanel jpOK = new JPanel(new FlowLayout(FlowLayout.CENTER));
		JButton jbOK = getOkButton(true);
		jpOK.add(jbOK);

		// Put it all together
		getContentPane().add(jpCSR, BorderLayout.NORTH);
		getContentPane().add(jpOK, BorderLayout.SOUTH);

		getRootPane().setDefaultButton(jbOK);

		initDialog();

		jbOK.requestFocusInWindow();
	}

	/**
	 * Populate the dialog with the currently selected certificate request's details.
	 * 
	 * @throws CryptoException A problem was encountered getting the certificate request's details
	 */
	private void populateDialog()
	    throws CryptoException
	{
		// Version
		m_jtfVersion.setText(m_req.toASN1Structure().getCertificationRequestInfo().getVersion().getValue().toString());
		m_jtfVersion.setCaretPosition(0);

		// Subject
		X500Name subject = m_req.getSubject();
		m_jtfSubject.setText(subject.toString());
		m_jtfSubject.setCaretPosition(0);

		m_basename = NameUtil.getCommonName(subject);

		// Public Key (algorithm and keysize)
		SubjectPublicKeyInfo keyInfo = m_req.getSubjectPublicKeyInfo();

		AsymmetricKeyParameter keyParams = null;
		try
		{
			keyParams = PublicKeyFactory.createKey(keyInfo);
		}
		catch (IOException e)
		{
			throw new CryptoException(RB.getString("DViewCSR.NoGetKeyInfo.exception.message"), e);
		}

		m_jtfPublicKey.setText(AlgorithmType.toString(keyInfo.getAlgorithm().getAlgorithm().toString()));

		int iKeySize = KeyPairUtil.getKeyLength(keyParams);
		if (iKeySize != KeyPairUtil.UNKNOWN_KEY_SIZE)
		{
			m_jtfPublicKey.setText(
			    MessageFormat.format(RB.getString("DViewCSR.m_jtfPublicKey.text"), m_jtfPublicKey.getText(), iKeySize));
		}
		m_jtfPublicKey.setCaretPosition(0);

		// Signature Algorithm
		String sigAlgName = SignatureType.toString(m_req.getSignatureAlgorithm().getAlgorithm().toString());
		m_jtfSignatureAlgorithm.setText(sigAlgName);
		m_jtfSignatureAlgorithm.setCaretPosition(0);

		// TODO: attributes, requested extensions
	}

	/**
	 * PEM Encoding Encoding button pressed or otherwise activated. Show the PEM encoding for the certification request.
	 */
	private void pemEncodingPressed()
	{
		JFileChooser chooser = FileChooserFactory.getCsrFileChooser(m_basename);
		// TODO: lastdir
		chooser.setDialogTitle(RB.getString("DViewCSR.Save.Title"));
		chooser.setMultiSelectionEnabled(false);
		try
		{
			DViewPEM dViewCertPem = new DViewPEM(this, RB.getString("DViewCSR.PemEncoding.Title"), m_req, chooser);
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
