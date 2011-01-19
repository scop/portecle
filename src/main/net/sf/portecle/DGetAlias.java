/*
 * DGetAlias.java
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
import java.awt.FlowLayout;
import java.awt.Window;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;

import net.sf.portecle.gui.SwingHelper;

/**
 * Modal dialog used for entering a keystore alias.
 */
class DGetAlias
    extends PortecleJDialog
{
	/** Alias text field */
	private JTextField m_jtfAlias;

	/** Stores the alias entered by the user */
	private String m_sAlias;

	/**
	 * Creates new DGetAlias dialog.
	 * 
	 * @param parent The parent window
	 * @param sTitle The dialog's title
	 * @param sOldAlias The alias to display initially
	 * @param select Whether to pre-select the initially displayed alias
	 */
	public DGetAlias(Window parent, String sTitle, String sOldAlias, boolean select)
	{
		super(parent, sTitle, true);
		initComponents(sOldAlias, select);
	}

	/**
	 * Get the alias entered by the user.
	 * 
	 * @return The alias, or null if none was entered
	 */
	public String getAlias()
	{
		return m_sAlias;
	}

	/**
	 * Initialize the dialog's GUI components.
	 * 
	 * @param sOldAlias The alias to display initially
	 * @param select Whether to pre-select the initially displayed alias
	 */
	private void initComponents(String sOldAlias, boolean select)
	{
		getContentPane().setLayout(new BorderLayout());

		JLabel jlAlias = new JLabel(RB.getString("DGetAlias.jlAlias.text"));
		m_jtfAlias = new JTextField(sOldAlias, 15);
		m_jtfAlias.setCaretPosition(sOldAlias.length());
		jlAlias.setLabelFor(m_jtfAlias);

		JButton jbOK = getOkButton(false);
		JButton jbCancel = getCancelButton();

		JPanel jpAlias = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpAlias.add(jlAlias);
		jpAlias.add(m_jtfAlias);
		jpAlias.setBorder(new EmptyBorder(5, 5, 5, 5));

		JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpButtons.add(jbOK);
		jpButtons.add(jbCancel);

		getContentPane().add(jpAlias, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		getRootPane().setDefaultButton(jbOK);

		initDialog();

		if (select)
		{
			SwingHelper.selectAndFocus(m_jtfAlias);
		}
	}

	/**
	 * Check that the alias is valid, i.e. that it is not blank.
	 * 
	 * @return True if the alias is valid, false otherwise
	 */
	private boolean checkAlias()
	{
		String sAlias = m_jtfAlias.getText().trim();

		if (!sAlias.isEmpty())
		{
			m_sAlias = sAlias;
			return true;
		}

		JOptionPane.showMessageDialog(this, RB.getString("DGetAlias.AliasReq.message"), getTitle(),
		    JOptionPane.WARNING_MESSAGE);

		SwingHelper.selectAndFocus(m_jtfAlias);
		return false;
	}

	@Override
	protected void okPressed()
	{
		if (checkAlias())
		{
			super.okPressed();
		}
	}
}
