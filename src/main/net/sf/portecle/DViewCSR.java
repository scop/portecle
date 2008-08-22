/*
 * DViewCSR.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2006 Ville Skyttä, ville.skytta@iki.fi
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
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.ResourceBundle;

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

import net.sf.portecle.crypto.AlgorithmType;
import net.sf.portecle.crypto.CryptoException;
import net.sf.portecle.crypto.KeyPairUtil;
import net.sf.portecle.crypto.NameUtil;
import net.sf.portecle.crypto.SignatureType;
import net.sf.portecle.gui.SwingHelper;
import net.sf.portecle.gui.crypto.DViewPEM;
import net.sf.portecle.gui.error.DThrowable;

import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.PKCS10CertificationRequest;

/**
 * Displays the details of a certification request.
 */
class DViewCSR
    extends JDialog
{
	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

	/** Version text field */
	private JTextField m_jtfVersion;

	/** Subject text field */
	private JTextField m_jtfSubject;

	/** Certificate Public Key text field */
	private JTextField m_jtfPublicKey;

	/** Certificate Signature Algorithm text field */
	private JTextField m_jtfSignatureAlgorithm;

	/** Stores request to display */
	private PKCS10CertificationRequest m_req;

	/** Default filename for saving */
	private String m_basename;

	/**
	 * Creates new DViewCSR dialog where the parent is a frame.
	 * 
	 * @param parent Parent frame
	 * @param sTitle The dialog title
	 * @param bModal Is dialog modal?
	 * @param req Certification request to display
	 * @throws CryptoException A problem was encountered getting the certification request details
	 */
	public DViewCSR(JFrame parent, String sTitle, boolean bModal, PKCS10CertificationRequest req)
	    throws CryptoException
	{
		super(parent, sTitle, bModal);
		m_req = req;
		initComponents();
	}

	/**
	 * Creates new DViewCSR dialog where the parent is a dialog.
	 * 
	 * @param parent Parent dialog
	 * @param sTitle The dialog title
	 * @param bModal Is dialog modal?
	 * @param req Certification request to display
	 * @throws CryptoException A problem was encountered getting the certification request details
	 */
	public DViewCSR(JDialog parent, String sTitle, boolean bModal, PKCS10CertificationRequest req)
	    throws CryptoException
	{
		super(parent, sTitle, bModal);
		m_req = req;
		initComponents();
	}

	/**
	 * Initialise the dialog's GUI components.
	 * 
	 * @throws CryptoException A problem was encountered getting the request details
	 */
	private void initComponents()
	    throws CryptoException
	{
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
		JLabel jlVersion = new JLabel(m_res.getString("DViewCSR.jlVersion.text"));
		GridBagConstraints gbc_jlVersion = (GridBagConstraints) gbcLbl.clone();
		gbc_jlVersion.gridy = 0;

		m_jtfVersion = new JTextField(3);
		m_jtfVersion.setEditable(false);
		m_jtfVersion.setToolTipText(m_res.getString("DViewCSR.m_jtfVersion.tooltip"));
		GridBagConstraints gbc_jtfVersion = (GridBagConstraints) gbcTf.clone();
		gbc_jtfVersion.gridy = 0;

		// Subject
		JLabel jlSubject = new JLabel(m_res.getString("DViewCSR.jlSubject.text"));
		GridBagConstraints gbc_jlSubject = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSubject.gridy = 1;

		m_jtfSubject = new JTextField(36);
		m_jtfSubject.setEditable(false);
		m_jtfSubject.setToolTipText(m_res.getString("DViewCSR.m_jtfSubject.tooltip"));
		GridBagConstraints gbc_jtfSubject = (GridBagConstraints) gbcTf.clone();
		gbc_jtfSubject.gridy = 1;

		// Public Key
		JLabel jlPublicKey = new JLabel(m_res.getString("DViewCSR.jlPublicKey.text"));
		GridBagConstraints gbc_jlPublicKey = (GridBagConstraints) gbcLbl.clone();
		gbc_jlPublicKey.gridy = 6;

		m_jtfPublicKey = new JTextField(15);
		m_jtfPublicKey.setEditable(false);
		m_jtfPublicKey.setToolTipText(m_res.getString("DViewCSR.m_jtfPublicKey.tooltip"));
		GridBagConstraints gbc_jtfPublicKey = (GridBagConstraints) gbcTf.clone();
		gbc_jtfPublicKey.gridy = 6;

		// Signature Algorithm
		JLabel jlSignatureAlgorithm = new JLabel(m_res.getString("DViewCSR.jlSignatureAlgorithm.text"));
		GridBagConstraints gbc_jlSignatureAlgorithm = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSignatureAlgorithm.gridy = 7;

		m_jtfSignatureAlgorithm = new JTextField(15);
		m_jtfSignatureAlgorithm.setEditable(false);
		m_jtfSignatureAlgorithm.setToolTipText(m_res.getString("DViewCSR.m_jtfSignatureAlgorithm.tooltip"));
		GridBagConstraints gbc_jtfSignatureAlgorithm = (GridBagConstraints) gbcTf.clone();
		gbc_jtfSignatureAlgorithm.gridy = 7;

		// TODO: attributes, requested extensions

		// PEM Encoding
		JButton jbPemEncoding = new JButton(m_res.getString("DViewCSR.jbPemEncoding.text"));
		jbPemEncoding.setMnemonic(m_res.getString("DViewCSR.jbPemEncoding.mnemonic").charAt(0));
		jbPemEncoding.setToolTipText(m_res.getString("DViewCSR.jbPemEncoding.tooltip"));
		jbPemEncoding.addActionListener(new ActionListener()
		{
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

		final JButton jbOK = new JButton(m_res.getString("DViewCSR.jbOK.text"));
		jbOK.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				okPressed();
			}
		});

		jpOK.add(jbOK);

		// Put it all together
		getContentPane().add(jpCSR, BorderLayout.NORTH);
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
	 * Populate the dialog with the currently selected certificate request's details.
	 * 
	 * @throws CryptoException A problem was encountered getting the certificate request's details
	 */
	private void populateDialog()
	    throws CryptoException
	{

		CertificationRequestInfo info = m_req.getCertificationRequestInfo();

		// Version
		m_jtfVersion.setText(info.getVersion().getValue().toString());
		m_jtfVersion.setCaretPosition(0);

		// Subject
		X509Name subject = info.getSubject();
		m_jtfSubject.setText(subject.toString());
		m_jtfSubject.setCaretPosition(0);

		m_basename = NameUtil.getCommonName(subject);

		// Public Key (algorithm and keysize)
		SubjectPublicKeyInfo keyInfo = info.getSubjectPublicKeyInfo();

		AsymmetricKeyParameter keyParams = null;
		try
		{
			keyParams = PublicKeyFactory.createKey(keyInfo);
		}
		catch (IOException e)
		{
			throw new CryptoException(m_res.getString("DViewCSR.NoGetKeyInfo.exception.message"), e);
		}

		m_jtfPublicKey.setText(AlgorithmType.forOid(keyInfo.getAlgorithmId().getObjectId().toString()).toString());

		int iKeySize = KeyPairUtil.getKeyLength(keyParams);
		if (iKeySize != -1)
		{
			m_jtfPublicKey.setText(MessageFormat.format(m_res.getString("DViewCSR.m_jtfPublicKey.text"),
			    m_jtfPublicKey.getText(), iKeySize));
		}
		m_jtfPublicKey.setCaretPosition(0);

		// Signature Algorithm
		String sigAlgName =
		    SignatureType.forOid(m_req.getSignatureAlgorithm().getObjectId().toString()).toString();
		m_jtfSignatureAlgorithm.setText(sigAlgName);
		m_jtfSignatureAlgorithm.setCaretPosition(0);

		// TODO: attributes, requested extensions
	}

	/**
	 * PEM Encoding Encoding button pressed or otherwise activated. Show the PEM encoding for the
	 * certification request.
	 */
	private void pemEncodingPressed()
	{
		JFileChooser chooser = FileChooserFactory.getCsrFileChooser(m_basename);
		// TODO: lastdir
		chooser.setDialogTitle(m_res.getString("DViewCSR.Save.Title"));
		chooser.setMultiSelectionEnabled(false);
		try
		{
			DViewPEM dViewCertPem =
			    new DViewPEM(this, m_res.getString("DViewCSR.PemEncoding.Title"), true, m_req, chooser);
			dViewCertPem.setLocationRelativeTo(this);
			SwingHelper.showAndWait(dViewCertPem);
		}
		catch (CryptoException ex)
		{
			DThrowable dThrowable = new DThrowable(this, true, ex);
			dThrowable.setLocationRelativeTo(this);
			SwingHelper.showAndWait(dThrowable);
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
