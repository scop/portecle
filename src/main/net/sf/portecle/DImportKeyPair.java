/*
 * DImportKeyPair.java
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package net.sf.portecle;

import static net.sf.portecle.FPortecle.RB;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Enumeration;
import java.util.Vector;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import net.sf.portecle.crypto.CryptoException;
import net.sf.portecle.crypto.KeyPairUtil;
import net.sf.portecle.crypto.X509CertUtil;
import net.sf.portecle.gui.SwingHelper;
import net.sf.portecle.gui.error.DThrowable;

/**
 * Dialog that displays the details of all key pairs from a PKCS #12 keystore allowing the user to pick one
 * for import.
 */
class DImportKeyPair
    extends JDialog
{
	/** Key from input map to action map for the cancel button */
	private static final String CANCEL_KEY = "CANCEL_KEY";

	/** List of key pairs available for import */
	private JList m_jltKeyPairs;

	/** Selected key pair's algorithm text field */
	private JTextField m_jtfAlgorithm;

	/** PKCS #12 keystore */
	private KeyStore m_pkcs12;

	/** Private key part of key pair chosen by the user for import */
	private Key m_privateKey;

	/** Certificate chain part of key pair chosen by the user for import */
	private Certificate[] m_certificateChain;

	/** Key pair alias in the source keystore */
	private String m_alias;

	/**
	 * Creates new DImportKeyPair.
	 * 
	 * @param parent The parent window
	 * @param modal Is dialog modal?
	 * @param pkcs12 The PKCS #12 keystore to list key pairs from
	 * @throws CryptoException A problem was encountered importing a key pair.
	 */
	public DImportKeyPair(Window parent, boolean modal, KeyStore pkcs12)
	    throws CryptoException
	{
		super(parent, (modal ? Dialog.DEFAULT_MODALITY_TYPE : Dialog.ModalityType.MODELESS));
		m_pkcs12 = pkcs12;
		initComponents();
	}

	/**
	 * Initialise the dialog's GUI components.
	 * 
	 * @throws CryptoException A problem was encountered importing a key pair
	 */
	private void initComponents()
	    throws CryptoException
	{
		// Instructions
		JLabel jlInstructions = new JLabel(RB.getString("DImportKeyPair.jlInstructions.text"));

		// Import button
		final JButton jbImport = new JButton(RB.getString("DImportKeyPair.jbImport.text"));
		jbImport.setEnabled(false);
		jbImport.setMnemonic(RB.getString("DImportKeyPair.jbImport.mnemonic").charAt(0));
		jbImport.setToolTipText(RB.getString("DImportKeyPair.jbImport.tooltip"));
		jbImport.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				importPressed();
			}
		});

		// Certificate details button
		final JButton jbCertificateDetails =
		    new JButton(RB.getString("DImportKeyPair.jbCertificateDetails.text"));
		jbCertificateDetails.setMnemonic(RB.getString("DImportKeyPair.jbCertificateDetails.mnemonic").charAt(
		    0));
		jbCertificateDetails.setToolTipText(RB.getString("DImportKeyPair.jbCertificateDetails.tooltip"));
		jbCertificateDetails.setEnabled(false);
		jbCertificateDetails.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				certificateDetailsPressed();
			}
		});

		// List to hold keystore's key pair aliases
		m_jltKeyPairs = new JList();
		m_jltKeyPairs.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		m_jltKeyPairs.addListSelectionListener(new ListSelectionListener()
		{
			public void valueChanged(ListSelectionEvent evt)
			{
				populateAlgorithm();
				if (m_jltKeyPairs.getSelectedIndex() == -1)
				{
					jbImport.setEnabled(false);
					jbCertificateDetails.setEnabled(false);
				}
				else
				{
					jbImport.setEnabled(true);
					jbCertificateDetails.setEnabled(true);
				}
			}
		});

		// Put the list into a scroll pane
		JScrollPane jspKeyPairs =
		    new JScrollPane(m_jltKeyPairs, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
		        JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		jspKeyPairs.getViewport().setBackground(m_jltKeyPairs.getBackground());

		// Key pair details (algorithm and button to access
		// certificate details)
		JLabel jlAlgorithm = new JLabel(RB.getString("DImportKeyPair.jlAlgorithm.text"));

		m_jtfAlgorithm = new JTextField(10);
		m_jtfAlgorithm.setText("");
		m_jtfAlgorithm.setToolTipText(RB.getString("DImportKeyPair.m_jtfAlgorithm.tooltip"));
		m_jtfAlgorithm.setEditable(false);

		JPanel jpKeyPairDetails = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpKeyPairDetails.add(jlAlgorithm);
		jpKeyPairDetails.add(m_jtfAlgorithm);
		jpKeyPairDetails.add(jbCertificateDetails);

		// Put all the key pair components together
		JPanel jpKeyPairs = new JPanel(new BorderLayout(10, 10));
		jpKeyPairs.setPreferredSize(new Dimension(400, 200));
		jpKeyPairs.setBorder(new CompoundBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5),
		    new EtchedBorder()), new EmptyBorder(5, 5, 5, 5)));

		jpKeyPairs.add(jlInstructions, BorderLayout.NORTH);
		jpKeyPairs.add(jspKeyPairs, BorderLayout.CENTER);
		jpKeyPairs.add(jpKeyPairDetails, BorderLayout.SOUTH);

		// Cancel button

		final JButton jbCancel = new JButton(RB.getString("DImportKeyPair.jbCancel.text"));
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
		jpButtons.add(jbImport);
		jpButtons.add(jbCancel);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpKeyPairs, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		// Populate the list
		populateList();

		addWindowListener(new WindowAdapter()
		{
			@Override
			public void windowClosing(WindowEvent evt)
			{
				closeDialog();
			}
		});

		setTitle(RB.getString("DImportKeyPair.Title"));
		setResizable(false);

		getRootPane().setDefaultButton(jbImport);

		pack();

		if (jbImport.isEnabled())
		{
			SwingUtilities.invokeLater(new Runnable()
			{
				public void run()
				{
					jbImport.requestFocus();
				}
			});
		}
		else
		{
			SwingUtilities.invokeLater(new Runnable()
			{
				public void run()
				{
					jbCancel.requestFocus();
				}
			});
		}
	}

	/**
	 * Populate the key pair list with the PKCS #12 keystore's key pair aliases.
	 * 
	 * @throws CryptoException Problem accessing the keystore's entries
	 */
	private void populateList()
	    throws CryptoException
	{
		try
		{
			Vector<String> vKeyPairAliases = new Vector<String>();

			// For each entry in the keystore...
			for (Enumeration<String> aliases = m_pkcs12.aliases(); aliases.hasMoreElements();)
			{
				// Get alias...
				String sAlias = aliases.nextElement();

				// Add the alias to the list if the entry has a key
				// and certificates
				if (m_pkcs12.isKeyEntry(sAlias))
				{
					m_pkcs12.getKey(sAlias, new char[] {}); // XXX: what's this, password check?
					Certificate[] certs = m_pkcs12.getCertificateChain(sAlias);

					if (certs != null && certs.length != 0)
					{
						vKeyPairAliases.add(sAlias);
					}
				}
			}

			if (vKeyPairAliases.size() > 0)
			{
				m_jltKeyPairs.setListData(vKeyPairAliases);
				m_jltKeyPairs.setSelectedIndex(0);
			}
			else
			{
				// No key pairs available...
				m_jltKeyPairs.setListData(new String[] { RB.getString("DImportKeyPair.m_jltKeyPairs.empty") });
				m_jltKeyPairs.setEnabled(false);
			}
		}
		catch (GeneralSecurityException ex)
		{
			throw new CryptoException(
			    RB.getString("DImportKeyPair.ProblemAccessingPkcs12.exception.message"), ex);
		}
	}

	/**
	 * Populate the algorithm text field. If a key pair is selected then the field will contain the key pairs
	 * algorithm name and key size. Otherwise the field will be blanked.
	 */
	private void populateAlgorithm()
	{
		try
		{
			String sAlias = (String) m_jltKeyPairs.getSelectedValue();

			if (sAlias == null)
			{
				m_jtfAlgorithm.setText("");
				return;
			}

			// Get the algorithm information from the appropriate
			// certificate - we can't yet use an API to get it
			// directly from the private key
			Certificate[] certs = m_pkcs12.getCertificateChain(sAlias);

			X509Certificate[] x509Certs = X509CertUtil.convertCertificates(certs);

			if (x509Certs == null)
			{
				m_jtfAlgorithm.setText("");
				return;
			}

			x509Certs = X509CertUtil.orderX509CertChain(x509Certs);

			X509Certificate keyPairCert = x509Certs[0];

			int iKeySize = KeyPairUtil.getKeyLength(keyPairCert.getPublicKey());
			m_jtfAlgorithm.setText(keyPairCert.getPublicKey().getAlgorithm());

			if (iKeySize != -1)
			{
				m_jtfAlgorithm.setText(MessageFormat.format(
				    RB.getString("DImportKeyPair.m_jtfAlgorithm.text"), m_jtfAlgorithm.getText(), iKeySize));
			}
			m_jtfAlgorithm.setCaretPosition(0);
		}
		catch (KeyStoreException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			closeDialog();
		}
		catch (CryptoException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			closeDialog();
		}
	}

	/**
	 * Certificate Details button pressed. Display the selected key pair's certificates.
	 */
	private void certificateDetailsPressed()
	{
		try
		{
			String sAlias = (String) m_jltKeyPairs.getSelectedValue();

			assert sAlias != null;

			X509Certificate[] certs = X509CertUtil.convertCertificates(m_pkcs12.getCertificateChain(sAlias));

			DViewCertificate dViewCertificate =
			    new DViewCertificate(this, MessageFormat.format(
			        RB.getString("DImportKeyPair.ViewCertificateDetails.Title"), sAlias), true, certs);
			dViewCertificate.setLocationRelativeTo(this);
			SwingHelper.showAndWait(dViewCertificate);
		}
		catch (KeyStoreException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			closeDialog();
		}
		catch (CryptoException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			closeDialog();
		}
	}

	/**
	 * Get the private part of the key pair chosen by the user for import.
	 * 
	 * @return The private key or null if the user has not chosen a key pair
	 */
	public Key getPrivateKey()
	{
		return m_privateKey;
	}

	/**
	 * Get the certificate chain part of the key pair chosen by the user for import.
	 * 
	 * @return The certificate chain or null if the user has not chosen a key pair
	 */
	public Certificate[] getCertificateChain()
	{
		return m_certificateChain;
	}

	/**
	 * Get the alias of the key pair chosen by the user for import.
	 * 
	 * @return the alias
	 */
	public String getAlias()
	{
		return m_alias;
	}

	/**
	 * Import button pressed by user. Store the selected key pair's private and public parts and close the
	 * dialog.
	 */
	public void importPressed()
	{
		String sAlias = (String) m_jltKeyPairs.getSelectedValue();

		assert sAlias != null;

		try
		{
			m_privateKey = m_pkcs12.getKey(sAlias, new char[] {});
			m_certificateChain = m_pkcs12.getCertificateChain(sAlias);
			m_alias = sAlias;
		}
		catch (KeyStoreException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			closeDialog();
		}
		catch (NoSuchAlgorithmException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			closeDialog();
		}
		catch (UnrecoverableKeyException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			closeDialog();
		}

		closeDialog();
	}

	/**
	 * Cancel button pressed - close the dialog.
	 */
	public void cancelPressed()
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
