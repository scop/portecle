/*
 * DAbout.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004-2008 Ville Skyttä, ville.skytta@iki.fi
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

import static net.sf.portecle.FPortecle.RB;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import net.sf.portecle.PortecleJDialog;
import net.sf.portecle.gui.SwingHelper;

/**
 * An About dialog which displays about information and a button to access system information.
 */
public class DAbout
    extends PortecleJDialog
{
	/**
	 * Creates new DAbout dialog.
	 * 
	 * @param parent Parent frame
	 */
	public DAbout(Window parent)
	{
		super(parent, RB.getString("DAbout.Title"), true);
		initComponents();
	}

	/**
	 * Initialize the dialog's GUI components.
	 */
	private void initComponents()
	{
		getContentPane().setLayout(new BorderLayout());

		JLabel jlAbout = new JLabel(RB.getString("DAbout.jlAbout.text"));

		JPanel jpAbout = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpAbout.setBorder(new EmptyBorder(5, 5, 5, 5));
		jpAbout.add(jlAbout);

		JButton jbOK = getOkButton(true);

		JButton jbSystemInformation = new JButton(RB.getString("DAbout.jbSystemInformation.text"));
		jbSystemInformation.setMnemonic(RB.getString("DAbout.jbSystemInformation.mnemonic").charAt(0));

		jbSystemInformation.addActionListener(new ActionListener()
		{
			@Override
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

		getRootPane().setDefaultButton(jbOK);

		initDialog();
	}

	/**
	 * Shows the System Information dialog.
	 */
	private void showSystemInformation()
	{
		DSystemInformation dSystemInformation = new DSystemInformation(this);
		dSystemInformation.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dSystemInformation);
	}
}
