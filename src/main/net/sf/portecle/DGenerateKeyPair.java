/*
 * DGenerateKeyPair.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2008 Ville Skyttä, ville.skytta@iki.fi
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
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.text.AbstractDocument;
import javax.swing.text.Document;
import javax.swing.text.JTextComponent;

import net.sf.portecle.crypto.KeyPairType;
import net.sf.portecle.gui.IntegerDocumentFilter;
import net.sf.portecle.gui.SwingHelper;

/**
 * Modal dialog used to choose the parameters required for key pair generation. The user may select an asymmetric key
 * generation algorithm of DSA or RSA and enter a key size in bits.
 */
class DGenerateKeyPair
    extends PortecleJDialog
{
	/** Indicator for an invalid key size */
	private static final int BAD_KEYSIZE = -1;

	/** Radio button for the DSA key algorithm */
	private JRadioButton m_jrbDSA;

	/** Radio button for the RSA key algorithm */
	private JRadioButton m_jrbRSA;

	/** Key size combo box */
	private JComboBox<String> m_jcbKeySize;

	/** Key pair type chosen for generation */
	private KeyPairType m_keyPairType;

	/** Key size chosen */
	private int m_iKeySize;

	/** Records whether or not correct parameters are entered */
	private boolean m_bSuccess;

	/**
	 * Creates new DGenerateKeyPair dialog.
	 * 
	 * @param parent The parent window
	 */
	public DGenerateKeyPair(Window parent)
	{
		super(parent, true);
		initComponents();
	}

	private void initComponents()
	{
		JLabel jlKeyAlg = new JLabel(RB.getString("DGenerateKeyPair.jlKeyAlg.text"));
		m_jrbDSA = new JRadioButton(RB.getString("DGenerateKeyPair.m_jrbDSA.text"), false);
		m_jrbDSA.setToolTipText(RB.getString("DGenerateKeyPair.m_jrbDSA.tooltip"));
		m_jrbRSA = new JRadioButton(RB.getString("DGenerateKeyPair.m_jrbRSA.text"), false);
		m_jrbRSA.setToolTipText(RB.getString("DGenerateKeyPair.m_jrbRSA.tooltip"));
		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(m_jrbDSA);
		buttonGroup.add(m_jrbRSA);

		JPanel jpKeyAlg = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpKeyAlg.add(m_jrbDSA);
		jpKeyAlg.add(m_jrbRSA);

		JLabel jlKeySize = new JLabel(RB.getString("DGenerateKeyPair.jlKeySize.text"));
		m_jcbKeySize = new JComboBox<>();
		m_jcbKeySize.setToolTipText(RB.getString("DGenerateKeyPair.m_jcbKeySize.tooltip"));
		m_jcbKeySize.setEditable(true);
		Component editor = m_jcbKeySize.getEditor().getEditorComponent();
		if (editor instanceof JTextComponent)
		{
			Document doc = ((JTextComponent) editor).getDocument();
			if (doc instanceof AbstractDocument)
			{
				((AbstractDocument) doc).setDocumentFilter(new IntegerDocumentFilter(5));
			}
		}
		jlKeySize.setLabelFor(m_jcbKeySize);

		ChangeListener keyAlgListener = new ChangeListener()
		{
			@Override
			public void stateChanged(ChangeEvent evt)
			{
				String keySizesKey = "DGenerateKeyPair.RsaKeySizes";
				String defaultSizeKey = "DGenerateKeyPair.DefaultRsaKeySize";
				if (m_jrbDSA.isSelected())
				{
					keySizesKey = "DGenerateKeyPair.DsaKeySizes";
					defaultSizeKey = "DGenerateKeyPair.DefaultDsaKeySize";
				}
				Object oldItem = m_jcbKeySize.getSelectedItem();
				boolean selectionKept = false;
				m_jcbKeySize.removeAllItems();
				for (String item : RB.getString(keySizesKey).split(",+"))
				{
					m_jcbKeySize.addItem(item);
					if (item.equals(oldItem))
					{
						m_jcbKeySize.setSelectedItem(item);
						selectionKept = true;
					}
				}
				if (!selectionKept)
				{
					m_jcbKeySize.setSelectedItem(RB.getString(defaultSizeKey));
				}
			}
		};
		m_jrbDSA.addChangeListener(keyAlgListener);
		m_jrbRSA.addChangeListener(keyAlgListener);
		m_jrbRSA.setSelected(true);

		JPanel jpOptions = new JPanel(new GridBagLayout());
		jpOptions.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));
		int gridy = 0;

		GridBagConstraints gbcLabel = new GridBagConstraints();
		gbcLabel.gridx = 0;
		gbcLabel.gridwidth = 1;
		gbcLabel.gridheight = 1;
		gbcLabel.insets = new Insets(5, 5, 5, 5);
		gbcLabel.anchor = GridBagConstraints.EAST;

		GridBagConstraints gbcField = new GridBagConstraints();
		gbcField.gridx = 1;
		gbcField.gridwidth = 1;
		gbcField.gridheight = 1;
		gbcField.insets = new Insets(5, 5, 5, 5);
		gbcField.anchor = GridBagConstraints.WEST;

		GridBagConstraints gbc = (GridBagConstraints) gbcLabel.clone();
		gbc.gridy = gridy;
		jpOptions.add(jlKeyAlg, gbc);

		gbc = (GridBagConstraints) gbcField.clone();
		gbc.gridy = gridy++;
		jpOptions.add(jpKeyAlg, gbc);

		gbc = (GridBagConstraints) gbcLabel.clone();
		gbc.gridy = gridy;
		jpOptions.add(jlKeySize, gbc);

		gbc = (GridBagConstraints) gbcField.clone();
		gbc.gridy = gridy++;
		jpOptions.add(m_jcbKeySize, gbc);

		JButton jbOK = getOkButton(false);
		JButton jbCancel = getCancelButton();

		JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpButtons.add(jbOK);
		jpButtons.add(jbCancel);

		getContentPane().add(jpOptions, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		setTitle(RB.getString("DGenerateKeyPair.Title"));

		getRootPane().setDefaultButton(jbOK);

		initDialog();

		SwingHelper.selectAndFocus(m_jcbKeySize);
	}

	/**
	 * Validate the chosen key pair generation parameters.
	 * 
	 * @return True if the key pair generation parameters are valid, false otherwise
	 */
	private boolean validateKeyGenParameters()
	{
		// Check key size
		int iKeySize = validateKeySize();
		if (iKeySize == BAD_KEYSIZE)
		{
			SwingHelper.selectAndFocus(m_jcbKeySize);
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
	 * Validate the key size value the user has entered as a string and convert it to an integer. Validate the key size
	 * is supported for the particular key pair generation algorithm they have chosen.
	 * 
	 * @return The Validity value or BAD_KEYSIZE if it is not valid
	 */
	private int validateKeySize()
	{
		String sKeySize = m_jcbKeySize.getSelectedItem().toString();
		int iKeySize;

		if (sKeySize.isEmpty())
		{
			JOptionPane.showMessageDialog(this, RB.getString("DGenerateKeyPair.KeySizeReq.message"), getTitle(),
			    JOptionPane.WARNING_MESSAGE);
			return BAD_KEYSIZE;
		}

		try
		{
			iKeySize = Integer.parseInt(sKeySize);
		}
		catch (NumberFormatException ex)
		{
			JOptionPane.showMessageDialog(this, RB.getString("DGenerateKeyPair.KeySizeIntegerReq.message"), getTitle(),
			    JOptionPane.WARNING_MESSAGE);
			return BAD_KEYSIZE;
		}

		if (m_jrbDSA.isSelected() && (iKeySize < 512 || iKeySize % 64 != 0))
		{
			JOptionPane.showMessageDialog(this, RB.getString("DGenerateKeyPair.UnsupportedDsaKeySize.message"),
			    getTitle(), JOptionPane.WARNING_MESSAGE);
			return BAD_KEYSIZE;
		}
		else if (iKeySize < 512)
		{
			JOptionPane.showMessageDialog(this, RB.getString("DGenerateKeyPair.UnsupportedRsaKeySize.message"),
			    getTitle(), JOptionPane.WARNING_MESSAGE);
			return BAD_KEYSIZE;
		}

		return iKeySize;
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

	@Override
	protected void okPressed()
	{
		if (validateKeyGenParameters())
		{
			super.okPressed();
		}
	}
}
