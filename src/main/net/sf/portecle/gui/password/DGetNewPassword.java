/*
 * DGetNewPassword.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2006-2008 Ville Skyttä, ville.skytta@iki.fi
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

package net.sf.portecle.gui.password;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.KeyStroke;
import javax.swing.border.EmptyBorder;

/**
 * Dialog used for entering and confirming a password.
 */
public class DGetNewPassword
    extends JDialog
{
	/** Key from input map to action map for the cancel button */
	private static final String CANCEL_KEY = "CANCEL_KEY";

	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/gui/password/resources");

	/** First password entry password field */
	private JPasswordField m_jpfFirst;

	/** Password confirmation entry password field */
	private JPasswordField m_jpfConfirm;

	/** Stores new password entered */
	private char[] m_cPassword;

	/**
	 * Creates new DGetNewPassword dialog.
	 * 
	 * @param parent Parent window
	 * @param sTitle The dialog's title
	 * @param modal Is dialog modal?
	 */
	public DGetNewPassword(Window parent, String sTitle, boolean modal)
	{
		super(parent, (sTitle == null) ? m_res.getString("DGetNewPassword.Title") : sTitle, (modal
		    ? Dialog.DEFAULT_MODALITY_TYPE : Dialog.ModalityType.MODELESS));
		initComponents();
	}

	/**
	 * Get the password set in the dialog.
	 * 
	 * @return The password or null if none was set
	 */
	public char[] getPassword()
	{
		if (m_cPassword == null)
		{
			return null;
		}
		char[] copy = new char[m_cPassword.length];
		System.arraycopy(m_cPassword, 0, copy, 0, copy.length);
		return copy;
	}

	/**
	 * Initialise the dialog's GUI components.
	 */
	private void initComponents()
	{
		getContentPane().setLayout(new BorderLayout());

		JLabel jlFirst = new JLabel(m_res.getString("DGetNewPassword.jlFirst.text"));
		JLabel jlConfirm = new JLabel(m_res.getString("DGetNewPassword.jlConfirm.text"));
		m_jpfFirst = new JPasswordField(15);
		m_jpfConfirm = new JPasswordField(15);

		JButton jbOK = new JButton(m_res.getString("DGetNewPassword.jbOK.text"));
		jbOK.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				okPressed();
			}
		});

		JButton jbCancel = new JButton(m_res.getString("DGetNewPassword.jbCancel.text"));
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

		JPanel jpPassword = new JPanel(new GridLayout(2, 2, 5, 5));
		jpPassword.add(jlFirst);
		jpPassword.add(m_jpfFirst);
		jpPassword.add(jlConfirm);
		jpPassword.add(m_jpfConfirm);
		jpPassword.setBorder(new EmptyBorder(5, 5, 5, 5));

		JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpButtons.add(jbOK);
		jpButtons.add(jbCancel);

		getContentPane().add(jpPassword, BorderLayout.CENTER);
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

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	/**
	 * Check for the following:
	 * <ul>
	 * <li>That the user has supplied and confirmed a password.
	 * <li>That the password's match.
	 * <li>That they have a length greater than a perscribed minimum.
	 * </ul>
	 * Store the new password in this object.
	 * 
	 * @return True, if the user's dialog entry matches the above criteria, false otherwise
	 */
	private boolean checkPassword()
	{
		String sFirstPassword = new String(m_jpfFirst.getPassword());
		String sConfirmPassword = new String(m_jpfConfirm.getPassword());

		if (sFirstPassword.equals(sConfirmPassword))
		{
			m_cPassword = sFirstPassword.toCharArray();
			return true;
		}

		JOptionPane.showMessageDialog(this, m_res.getString("PasswordsNoMatch.message"), getTitle(),
		    JOptionPane.WARNING_MESSAGE);

		return false;
	}

	/**
	 * OK button pressed or otherwise activated.
	 */
	private void okPressed()
	{
		if (checkPassword())
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
	 * Close the dialog.
	 */
	private void closeDialog()
	{
		setVisible(false);
		dispose();
	}
}
