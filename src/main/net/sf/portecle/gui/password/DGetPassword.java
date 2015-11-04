/*
 * DGetPassword.java
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
import java.awt.Window;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.border.EmptyBorder;

import org.bouncycastle.openssl.PasswordFinder;

import net.sf.portecle.PortecleJDialog;

/**
 * Modal dialog used for entering a masked password.
 */
public class DGetPassword
    extends PortecleJDialog
    implements PasswordFinder
{
	/** Password entry password field */
	private JPasswordField m_jpfPassword;

	/** Stores password entered */
	private char[] m_cPassword;

	/**
	 * Creates new DGetPassword dialog.
	 * 
	 * @param parent Parent frame
	 * @param sTitle The dialog's title
	 */
	public DGetPassword(Window parent, String sTitle)
	{
		super(parent, sTitle, true);
		initComponents();
	}

	/**
	 * Get the password set in the dialog.
	 * 
	 * @return The password or null if none was set
	 */
	@Override
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

		JLabel jlPassword = new JLabel(RB.getString("DGetPassword.jlPassword.text"));
		m_jpfPassword = new JPasswordField(15);
		jlPassword.setLabelFor(m_jpfPassword);

		JPanel jpPassword = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpPassword.add(jlPassword);
		jpPassword.add(m_jpfPassword);
		jpPassword.setBorder(new EmptyBorder(5, 5, 5, 5));

		JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
		JButton jbOK = getOkButton(false);
		JButton jbCancel = getCancelButton();

		jpButtons.add(jbOK);
		jpButtons.add(jbCancel);

		getContentPane().add(jpPassword, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		getRootPane().setDefaultButton(jbOK);

		initDialog();
	}

	@Override
	protected void okPressed()
	{
		m_cPassword = m_jpfPassword.getPassword();
		super.okPressed();
	}
}
