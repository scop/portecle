/*
 * PortecleDialog.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2009 Ville Skyttä, ville.skytta@iki.fi
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

import java.awt.Dialog;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.KeyStroke;

/**
 * Base class for Portecle's dialogs.
 */
public class PortecleJDialog
    extends JDialog
{
	/** Key from input map to action map for the cancel button */
	private static final String CANCEL_KEY = PortecleJDialog.class.getName() + ".CANCEL_KEY";

	public PortecleJDialog(Window parent, boolean modal)
	{
		super(parent, modal ? Dialog.DEFAULT_MODALITY_TYPE : Dialog.ModalityType.MODELESS);
	}

	public PortecleJDialog(Window parent, String title, boolean modal)
	{
		super(parent, title, modal ? Dialog.DEFAULT_MODALITY_TYPE : Dialog.ModalityType.MODELESS);
	}

	/**
	 * Initialise the dialog.
	 */
	protected void initDialog()
	{
		addWindowListener(new WindowAdapter()
		{
			@Override
			public void windowClosing(WindowEvent evt)
			{
				closeDialog();
			}
		});

		setResizable(false);

		pack();
	}

	/**
	 * Get OK button.
	 * 
	 * @return
	 */
	protected JButton getOkButton()
	{
		JButton jbOK = new JButton(RB.getString("PortecleJDialog.jbOk.text"));
		jbOK.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				okPressed();
			}
		});

		return jbOK;
	}

	/**
	 * Get cancel button.
	 * 
	 * @return
	 */
	protected JButton getCancelButton()
	{
		Action cancelAction = new AbstractAction()
		{
			public void actionPerformed(ActionEvent evt)
			{
				cancelPressed();
			}
		};
		JButton jbCancel = new JButton(RB.getString("PortecleJDialog.jbCancel.text"));
		jbCancel.addActionListener(cancelAction);
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
		    KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);
		jbCancel.getActionMap().put(CANCEL_KEY, cancelAction);

		return jbCancel;
	}

	/**
	 * OK button pressed or otherwise activated.
	 */
	protected void okPressed()
	{
		closeDialog();
	}

	/**
	 * Cancel button pressed or otherwise activated.
	 */
	protected void cancelPressed()
	{
		closeDialog();
	}

	/**
	 * Closes the dialog.
	 */
	protected void closeDialog()
	{
		setVisible(false);
		dispose();
	}
}
