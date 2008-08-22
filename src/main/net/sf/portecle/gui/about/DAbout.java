/*
 * DAbout.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004 Ville Skyttä, ville.skytta@iki.fi
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

package net.sf.portecle.gui.about;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import net.sf.portecle.gui.SwingHelper;

/**
 * An About dialog which displays about information and a button to access system information.
 */
public class DAbout
    extends JDialog
{
	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/gui/about/resources");

	/**
	 * Creates new DAbout dialog where the parent is a frame.
	 * 
	 * @param parent Parent frame
	 * @param bModal Is dialog modal?
	 */
	public DAbout(JFrame parent, boolean bModal)
	{
		this(parent, m_res.getString("DAbout.Title"), bModal);
	}

	/**
	 * Creates new DAbout dialog where the parent is a frame.
	 * 
	 * @param parent Parent frame
	 * @param sTitle The title of the dialog
	 * @param bModal Is dialog modal?
	 */
	public DAbout(JFrame parent, String sTitle, boolean bModal)
	{
		super(parent, sTitle, bModal);
		initComponents();
	}

	/**
	 * Initialise the dialog's GUI components.
	 */
	private void initComponents()
	{
		getContentPane().setLayout(new BorderLayout());

		JLabel jlAbout = new JLabel(m_res.getString("DAbout.jlAbout.text"));

		JPanel jpAbout = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpAbout.setBorder(new EmptyBorder(5, 5, 5, 5));
		jpAbout.add(jlAbout);

		JButton jbOK = new JButton(m_res.getString("DAbout.jbOK.text"));
		jbOK.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				okPressed();
			}
		});

		JButton jbSystemInformation = new JButton(m_res.getString("DAbout.jbSystemInformation.text"));
		jbSystemInformation.setMnemonic(m_res.getString("DAbout.jbSystemInformation.mnemonic").charAt(0));

		jbSystemInformation.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				showSystemInformation();
			}
		});

		JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpButtons.setBorder(new EmptyBorder(5, 0, 5, 0));
		jpButtons.add(jbOK);
		jpButtons.add(jbSystemInformation);

		getContentPane().add(jpAbout, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		setResizable(false);

		addWindowListener(new WindowAdapter()
		{
			@Override
			public void windowClosing(WindowEvent evt)
			{
				closeDialog();
			}
		});

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	/**
	 * Shows the System Information dialog.
	 */
	private void showSystemInformation()
	{
		DSystemInformation dSystemInformation = new DSystemInformation(this, true);
		dSystemInformation.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dSystemInformation);
	}

	/**
	 * OK button pressed or otherwise activated.
	 */
	private void okPressed()
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
