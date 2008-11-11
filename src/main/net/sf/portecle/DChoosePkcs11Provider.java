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
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.Provider;
import java.security.Security;
import java.text.MessageFormat;
import java.util.TreeSet;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.KeyStroke;
import javax.swing.border.EmptyBorder;

import net.sf.portecle.crypto.ProviderUtil;

/**
 * Dialog used for choosing a PKCS #11 provider.
 * 
 * @author Ville Skyttä
 */
public class DChoosePkcs11Provider
    extends JDialog
{
	/** Key from input map to action map for the cancel button */
	private static final String CANCEL_KEY = "CANCEL_KEY";

	/** Provider drop-down box */
	private JComboBox m_jcbProvider;

	/** Stores the provider chosen by the user */
	private String m_sProvider;

	/**
	 * Creates new DChoosePkcs11Provider dialog.
	 * 
	 * @param parent The parent window
	 * @param sTitle The dialog's title
	 * @param modal Is the dialog modal?
	 * @param sOldProvider The provider to display initially
	 */
	public DChoosePkcs11Provider(Window parent, String sTitle, boolean modal, String sOldProvider)
	{
		super(parent, sTitle, (modal ? Dialog.DEFAULT_MODALITY_TYPE : Dialog.ModalityType.MODELESS));
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
	 * Initialise the dialog's GUI components.
	 * 
	 * @param sOldProvider The provider to display initially
	 */
	private void initComponents(String sOldProvider)
	{
		getContentPane().setLayout(new BorderLayout());

		JLabel jlProvider = new JLabel(RB.getString("DChoosePkcs11Provider.jlProvider.text"));
		m_jcbProvider = new JComboBox();
		m_jcbProvider.setToolTipText(RB.getString("DChoosePkcs11Provider.m_jcbProvider.tooltip"));

		TreeSet<Provider> pSet = new TreeSet<Provider>(ProviderUtil.getPkcs11Providers());

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

		JButton jbOK = new JButton(RB.getString("DChoosePkcs11Provider.jbOK.text"));
		if (providersAvailable)
		{
			jbOK.addActionListener(new ActionListener()
			{
				public void actionPerformed(ActionEvent evt)
				{
					okPressed();
				}
			});
		}
		else
		{
			jbOK.setEnabled(false);
		}

		JButton jbCancel = new JButton(RB.getString("DChoosePkcs11Provider.jbCancel.text"));
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

		JPanel jpProvider = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpProvider.add(jlProvider);
		jpProvider.add(m_jcbProvider);
		jpProvider.setBorder(new EmptyBorder(5, 5, 5, 5));

		JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpButtons.add(jbOK);
		jpButtons.add(jbCancel);

		getContentPane().add(jpProvider, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter()
		{
			@Override
			public void windowClosing(WindowEvent evt)
			{
				closeDialog();
			}
		});

		setResizable(false);

		getRootPane().setDefaultButton(providersAvailable ? jbOK : jbCancel);

		pack();
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
			String msg =
			    MessageFormat.format(RB.getString("DChoosePkcs11Provider.InvalidProvider.message"), sProvider);
			JOptionPane.showMessageDialog(this, msg, getTitle(), JOptionPane.WARNING_MESSAGE);
			return false;
		}

		m_sProvider = sProvider;
		return true;
	}

	/**
	 * OK button pressed or otherwise activated.
	 */
	private void okPressed()
	{
		if (checkProvider())
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

	/** Closes the dialog */
	private void closeDialog()
	{
		setVisible(false);
		dispose();
	}
}
