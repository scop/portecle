/*
 * DGetAlias.java
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
import java.awt.Dialog;
import java.awt.FlowLayout;
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
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.border.EmptyBorder;

import net.sf.portecle.gui.SwingHelper;

/**
 * Dialog used for entering a keystore alias.
 */
class DGetAlias
    extends JDialog
{
	/** Key from input map to action map for the cancel button */
	private static final String CANCEL_KEY = "CANCEL_KEY";

	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

	/** Alias text field */
	private JTextField m_jtfAlias;

	/** Stores the alias entered by the user */
	private String m_sAlias;

	/**
	 * Creates new DGetAlias dialog.
	 * 
	 * @param parent The parent window
	 * @param sTitle The dialog's title
	 * @param modal Is the dialog modal?
	 * @param sOldAlias The alias to display initially
	 * @param select Whether to pre-select the initially displayed alias
	 */
	public DGetAlias(Window parent, String sTitle, boolean modal, String sOldAlias, boolean select)
	{
		super(parent, sTitle, (modal ? Dialog.DEFAULT_MODALITY_TYPE : Dialog.ModalityType.MODELESS));
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
	 * Initialise the dialog's GUI components.
	 * 
	 * @param sOldAlias The alias to display initially
	 * @param select Whether to pre-select the initially displayed alias
	 */
	private void initComponents(String sOldAlias, boolean select)
	{
		getContentPane().setLayout(new BorderLayout());

		JLabel jlAlias = new JLabel(m_res.getString("DGetAlias.jlAlias.text"));
		m_jtfAlias = new JTextField(15);

		if (sOldAlias != null)
		{
			m_jtfAlias.setText(sOldAlias);
			m_jtfAlias.setCaretPosition(0);
		}

		JButton jbOK = new JButton(m_res.getString("DGetAlias.jbOK.text"));
		jbOK.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				okPressed();
			}
		});

		JButton jbCancel = new JButton(m_res.getString("DGetAlias.jbCancel.text"));
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

		JPanel jpAlias = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpAlias.add(jlAlias);
		jpAlias.add(m_jtfAlias);
		jpAlias.setBorder(new EmptyBorder(5, 5, 5, 5));

		JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpButtons.add(jbOK);
		jpButtons.add(jbCancel);

		getContentPane().add(jpAlias, BorderLayout.CENTER);
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

		if (select)
		{
			SwingHelper.selectAndFocus(m_jtfAlias);
		}
	}

	/**
	 * Check that the alias is valid, ie that it is not blank.
	 * 
	 * @return True if the alias is valid, false otherwise
	 */
	private boolean checkAlias()
	{
		String sAlias = m_jtfAlias.getText().trim();

		if (sAlias.length() > 0)
		{
			m_sAlias = sAlias;
			return true;
		}

		JOptionPane.showMessageDialog(this, m_res.getString("DGetAlias.AliasReq.message"), getTitle(),
		    JOptionPane.WARNING_MESSAGE);

		SwingHelper.selectAndFocus(m_jtfAlias);
		return false;
	}

	/**
	 * OK button pressed or otherwise activated.
	 */
	private void okPressed()
	{
		if (checkAlias())
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
