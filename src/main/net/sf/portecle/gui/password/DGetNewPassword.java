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

import static net.sf.portecle.FPortecle.RB;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.Window;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.border.EmptyBorder;

import net.sf.portecle.PortecleJDialog;

/**
 * Modal dialog used for entering and confirming a password.
 */
public class DGetNewPassword
    extends PortecleJDialog
{
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
	 */
	public DGetNewPassword(Window parent, String sTitle)
	{
		super(parent, (sTitle == null) ? RB.getString("DGetNewPassword.Title") : sTitle, true);
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
	 * Initialize the dialog's GUI components.
	 */
	private void initComponents()
	{
		getContentPane().setLayout(new BorderLayout());

		JLabel jlFirst = new JLabel(RB.getString("DGetNewPassword.jlFirst.text"));
		JLabel jlConfirm = new JLabel(RB.getString("DGetNewPassword.jlConfirm.text"));
		m_jpfFirst = new JPasswordField(15);
		m_jpfConfirm = new JPasswordField(15);
		jlFirst.setLabelFor(m_jpfFirst);
		jlConfirm.setLabelFor(m_jpfConfirm);

		JButton jbOK = getOkButton(false);
		JButton jbCancel = getCancelButton();

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

		getRootPane().setDefaultButton(jbOK);

		initDialog();
	}

	/**
	 * Check for the following:
	 * <ul>
	 * <li>That the user has supplied and confirmed a password.
	 * <li>That the passwords match.
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

		JOptionPane.showMessageDialog(this, RB.getString("PasswordsNoMatch.message"), getTitle(),
		    JOptionPane.WARNING_MESSAGE);

		return false;
	}

	@Override
	protected void okPressed()
	{
		if (checkPassword())
		{
			super.okPressed();
		}
	}
}
