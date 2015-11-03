/*
 * DChangePassword.java
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
 * Modal dialog used for entering and confirming a password and checking it against an old password which may or may not
 * have been supplied to the dialog.
 */
public class DChangePassword
    extends PortecleJDialog
{
	/** Old password entry password field */
	private JPasswordField m_jpfOld;

	/** First password entry password field */
	private JPasswordField m_jpfFirst;

	/** Password confirmation entry password field */
	private JPasswordField m_jpfConfirm;

	/** Stores new password entered */
	private char[] m_cNewPassword;

	/** Stores old password entered/supplied */
	private char[] m_cOldPassword;

	/**
	 * Creates new DChangePassword dialog.
	 * 
	 * @param parent Parent window
	 * @param sTitle Is dialog modal?
	 * @param cOldPassword The password to be changed
	 */
	public DChangePassword(Window parent, String sTitle, char[] cOldPassword)
	{
		super(parent, (sTitle == null) ? RB.getString("DChangePassword.Title") : sTitle, true);
		m_cOldPassword = arrayCopy(cOldPassword);
		initComponents();
	}

	/**
	 * Get the new password set in the dialog.
	 * 
	 * @return The new password or null if none was set
	 */
	public char[] getNewPassword()
	{
		return arrayCopy(m_cNewPassword);
	}

	/**
	 * Get the old password set in the dialog.
	 * 
	 * @return The old password or null if none was set/supplied
	 */
	public char[] getOldPassword()
	{
		return arrayCopy(m_cOldPassword);
	}

	/**
	 * Copies a char array.
	 * 
	 * @param original
	 * @return a copy of the given char array
	 */
	private static final char[] arrayCopy(char[] original)
	{
		char[] copy = null;
		if (original != null)
		{
			copy = new char[original.length];
			System.arraycopy(original, 0, copy, 0, copy.length);
		}
		return copy;
	}

	/**
	 * Initialize the dialog's GUI components.
	 */
	private void initComponents()
	{
		getContentPane().setLayout(new BorderLayout());

		JLabel jlFirst = new JLabel(RB.getString("DChangePassword.jlFirst.text"));
		m_jpfFirst = new JPasswordField(15);
		jlFirst.setLabelFor(m_jpfFirst);

		JLabel jlConfirm = new JLabel(RB.getString("DChangePassword.jlConfirm.text"));
		m_jpfConfirm = new JPasswordField(15);
		jlConfirm.setLabelFor(m_jpfConfirm);

		JLabel jlOld = new JLabel(RB.getString("DChangePassword.jlOld.text"));

		// Old password was supplied - just disable the old password field after filling it with junk
		if (m_cOldPassword != null)
		{
			m_jpfOld = new JPasswordField("1234567890", 15);
			m_jpfOld.setEnabled(false);
		}
		else
		{
			m_jpfOld = new JPasswordField(10);
		}
		jlOld.setLabelFor(m_jpfOld);

		JButton jbOK = getOkButton(false);
		JButton jbCancel = getCancelButton();

		JPanel jpPassword = new JPanel(new GridLayout(3, 2, 5, 5));
		jpPassword.add(jlOld);
		jpPassword.add(m_jpfOld);
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
	 * <li>That the old password was supplied or set by the user.
	 * </ul>
	 * Store the old and changed password in this object.
	 * 
	 * @return True, if the user's dialog entry matches the above criteria, false otherwise
	 */
	private boolean checkPassword()
	{
		String sOldPassword = new String(m_jpfOld.getPassword());
		String sFirstPassword = new String(m_jpfFirst.getPassword());
		String sConfirmPassword = new String(m_jpfConfirm.getPassword());

		if (sFirstPassword.equals(sConfirmPassword))
		{
			if (m_cOldPassword == null)
			{
				m_cOldPassword = sOldPassword.toCharArray();
			}
			m_cNewPassword = sFirstPassword.toCharArray();
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
