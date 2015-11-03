/*
 * DChoosePkcs11Provider.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004-2008 Ville Skyttä, ville.skytta@iki.fi
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
import java.awt.Window;
import java.security.Provider;
import java.security.Security;
import java.text.MessageFormat;
import java.util.TreeSet;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import net.sf.portecle.crypto.ProviderUtil;

/**
 * Modal dialog used for choosing a PKCS #11 provider.
 * 
 * @author Ville Skyttä
 */
/* package private */class DChoosePkcs11Provider
    extends PortecleJDialog
{
	/** Provider drop-down box */
	private JComboBox<String> m_jcbProvider;

	/** Stores the provider chosen by the user */
	private String m_sProvider;

	/**
	 * Creates new DChoosePkcs11Provider dialog.
	 * 
	 * @param parent The parent window
	 * @param sTitle The dialog's title
	 * @param sOldProvider The provider to display initially
	 */
	public DChoosePkcs11Provider(Window parent, String sTitle, String sOldProvider)
	{
		super(parent, sTitle, true);
		initComponents(sOldProvider);
	}

	/**
	 * Get the provider chosen by the user.
	 * 
	 * @return The provider, or null if none was entered
	 */
	public String getProvider()
	{
		return m_sProvider;
	}

	/**
	 * Initialize the dialog's GUI components.
	 * 
	 * @param sOldProvider The provider to display initially
	 */
	private void initComponents(String sOldProvider)
	{
		getContentPane().setLayout(new BorderLayout());

		JLabel jlProvider = new JLabel(RB.getString("DChoosePkcs11Provider.jlProvider.text"));
		m_jcbProvider = new JComboBox<>();
		m_jcbProvider.setToolTipText(RB.getString("DChoosePkcs11Provider.m_jcbProvider.tooltip"));
		jlProvider.setLabelFor(m_jcbProvider);

		TreeSet<Provider> pSet = new TreeSet<>(ProviderUtil.getPkcs11Providers());

		boolean providersAvailable = !pSet.isEmpty();

		if (providersAvailable)
		{
			for (Provider prov : pSet)
			{
				String pName = prov.getName();
				m_jcbProvider.addItem(pName);
				if (pName.equals(sOldProvider))
				{
					m_jcbProvider.setSelectedIndex(m_jcbProvider.getItemCount() - 1);
				}
			}
		}
		else
		{
			m_jcbProvider.addItem(RB.getString("DChoosePkcs11Provider.NoPkcs11Providers"));
			m_jcbProvider.setEnabled(false);
		}

		JButton jbOK = getOkButton(false);
		jbOK.setEnabled(providersAvailable);
		JButton jbCancel = getCancelButton();

		JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpButtons.add(jbOK);
		jpButtons.add(jbCancel);

		JPanel jpProvider = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpProvider.add(jlProvider);
		jpProvider.add(m_jcbProvider);
		jpProvider.setBorder(new EmptyBorder(5, 5, 5, 5));

		getContentPane().add(jpProvider, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		getRootPane().setDefaultButton(providersAvailable ? jbOK : jbCancel);

		initDialog();
	}

	/**
	 * Check that the chosen provider is valid.
	 * 
	 * @return True if the provider is valid, false otherwise
	 */
	private boolean checkProvider()
	{
		String sProvider = (String) m_jcbProvider.getSelectedItem();

		if (sProvider == null || Security.getProvider(sProvider) == null)
		{
			String msg = MessageFormat.format(RB.getString("DChoosePkcs11Provider.InvalidProvider.message"), sProvider);
			JOptionPane.showMessageDialog(this, msg, getTitle(), JOptionPane.WARNING_MESSAGE);
			return false;
		}

		m_sProvider = sProvider;
		return true;
	}

	@Override
	protected void okPressed()
	{
		if (checkProvider())
		{
			super.okPressed();
		}
	}
}
