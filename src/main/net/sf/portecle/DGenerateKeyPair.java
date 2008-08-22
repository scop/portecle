/*
 * DGenerateKeyPair.java
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

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import net.sf.portecle.crypto.KeyPairType;

/**
 * Dialog used to choose the parameters required for key pair generation. The user may select an asymmetric
 * key generation algorithm of DSA or RSA and enter a key size in bits.
 */
class DGenerateKeyPair
    extends JDialog
{
	/** Key from input map to action map for the cancel button */
	private static final String CANCEL_KEY = "CANCEL_KEY";

	/** Indicator for an invalid keysize */
	private static final int BAD_KEYSIZE = -1;

	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

	/** Default keysize for the dialog */
	private static String DEFAULT_KEYSIZE = m_res.getString("DGenerateKeyPair.DefaultKeySize");

	/** Radio button for the DSA key algorithm */
	private JRadioButton m_jrbDSA;

	/** Radio button for the RSA key algorithm */
	private JRadioButton m_jrbRSA;

	/** Key size text field */
	private JTextField m_jtfKeySize;

	/** Key pair type chosen for generation */
	private KeyPairType m_keyPairType;

	/** Key size chosen */
	private int m_iKeySize;

	/** Records whether or not correct parameters are entered */
	private boolean m_bSuccess;

	/**
	 * Creates new DGenerateKeyPair dialog where the parent is a frame.
	 * 
	 * @param parent The parent frame
	 * @param bModal Is dialog modal?
	 */
	public DGenerateKeyPair(JFrame parent, boolean bModal)
	{
		super(parent, bModal);
		initComponents();
	}

	/**
	 * Creates new DGenerateKeyPair dialog where the parent is a dialog.
	 * 
	 * @param parent The parent dialog
	 * @param bModal Is dialog modal?
	 */
	public DGenerateKeyPair(JDialog parent, boolean bModal)
	{
		super(parent, bModal);
		initComponents();
	}

	/**
	 * Initialise the dialog's GUI components.
	 */
	private void initComponents()
	{
		JLabel jlKeyAlg = new JLabel(m_res.getString("DGenerateKeyPair.jlKeyAlg.text"));
		m_jrbDSA = new JRadioButton(m_res.getString("DGenerateKeyPair.m_jrbDSA.text"), true);
		m_jrbDSA.setToolTipText(m_res.getString("DGenerateKeyPair.m_jrbDSA.tooltip"));
		m_jrbRSA = new JRadioButton(m_res.getString("DGenerateKeyPair.m_jrbRSA.text"), false);
		m_jrbRSA.setToolTipText(m_res.getString("DGenerateKeyPair.m_jrbRSA.tooltip"));
		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(m_jrbDSA);
		buttonGroup.add(m_jrbRSA);
		JPanel jpKeyAlg = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpKeyAlg.add(jlKeyAlg);
		jpKeyAlg.add(m_jrbDSA);
		jpKeyAlg.add(m_jrbRSA);

		JLabel jlKeySize = new JLabel(m_res.getString("DGenerateKeyPair.jlKeySize.text"));
		m_jtfKeySize = new JTextField(5);
		m_jtfKeySize.setText(DEFAULT_KEYSIZE);
		m_jtfKeySize.setToolTipText(m_res.getString("DGenerateKeyPair.m_jtfKeySize.tooltip"));
		JPanel jpKeySize = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpKeySize.add(jlKeySize);
		jpKeySize.add(m_jtfKeySize);

		JPanel jpOptions = new JPanel(new GridLayout(2, 1, 5, 5));
		jpOptions.add(jpKeyAlg);
		jpOptions.add(jpKeySize);

		jpOptions.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		JButton jbOK = new JButton(m_res.getString("DGenerateKeyPair.jbOK.text"));
		jbOK.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				okPressed();
			}
		});

		JButton jbCancel = new JButton(m_res.getString("DGenerateKeyPair.jbCancel.text"));
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

		setTitle(m_res.getString("DGenerateKeyPair.Title"));
		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	/**
	 * Validate the chosen key pair generation parameters.
	 * 
	 * @return True if the key pair generation paremeters are valid, false otherwise
	 */
	private boolean validateKeyGenParameters()
	{
		// Check key size
		int iKeySize = validateKeySize();
		if (iKeySize == BAD_KEYSIZE)
		{
			return false; // Invalid
		}
		m_iKeySize = iKeySize;

		// Get key pair generation algorithm
		if (m_jrbDSA.isSelected())
		{
			m_keyPairType = KeyPairType.DSA;
		}
		else
		{
			m_keyPairType = KeyPairType.RSA;
		}

		m_bSuccess = true;

		// Key pair generation parameters verified
		return true;
	}

	/**
	 * Validate the key size value the user has entered as a string and convert it to an integer. Validate the
	 * key size is supported for the particular key pair generation algorithm they have chosen.
	 * 
	 * @return The Validity value or BAD_KEYSIZE if it is not valid
	 */
	private int validateKeySize()
	{
		String sKeySize = m_jtfKeySize.getText().trim();
		int iKeySize;

		if (sKeySize.length() == 0)
		{
			JOptionPane.showMessageDialog(this, m_res.getString("DGenerateKeyPair.KeySizeReq.message"),
			    getTitle(), JOptionPane.WARNING_MESSAGE);
			return BAD_KEYSIZE;
		}

		try
		{
			iKeySize = Integer.parseInt(sKeySize);
		}
		catch (NumberFormatException ex)
		{
			JOptionPane.showMessageDialog(this,
			    m_res.getString("DGenerateKeyPair.KeySizeIntegerReq.message"), getTitle(),
			    JOptionPane.WARNING_MESSAGE);
			return BAD_KEYSIZE;
		}

		if (m_jrbDSA.isSelected() && (iKeySize < 512 || iKeySize > 1024 || iKeySize % 64 != 0))
		{
			JOptionPane.showMessageDialog(this,
			    m_res.getString("DGenerateKeyPair.UnsupportedDsaKeySize.message"), getTitle(),
			    JOptionPane.WARNING_MESSAGE);
			return BAD_KEYSIZE;
		}
		else if (iKeySize < 512)
		{
			JOptionPane.showMessageDialog(this,
			    m_res.getString("DGenerateKeyPair.UnsupportedRsaKeySize.message"), getTitle(),
			    JOptionPane.WARNING_MESSAGE);
			return BAD_KEYSIZE;
		}

		return iKeySize;
	}

	/**
	 * OK button pressed or otherwise activated.
	 */
	private void okPressed()
	{
		if (validateKeyGenParameters())
		{
			closeDialog();
		}
	}

	/**
	 * Get the key pair size chosen.
	 * 
	 * @return The key pair size
	 */
	public int getKeySize()
	{
		return m_iKeySize;
	}

	/**
	 * Get the key pair type chosen.
	 * 
	 * @return The key pair generation type
	 */
	public KeyPairType getKeyPairType()
	{
		return m_keyPairType;
	}

	/**
	 * Have the parameters been entered correctly?
	 * 
	 * @return True if they have, false otherwise
	 */
	public boolean isSuccessful()
	{
		return m_bSuccess;
	}

	/**
	 * Cancel button pressed or otherwise activated.
	 */
	private void cancelPressed()
	{
		closeDialog();
	}

	/** Closes the dialog */
	private void closeDialog()
	{
		setVisible(false);
		dispose();
	}
}
