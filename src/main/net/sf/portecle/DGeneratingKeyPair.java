/*
 * DGeneratingKeyPair.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2011 Ville Skyttä, ville.skytta@iki.fi
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
import java.security.KeyPair;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingWorker;
import javax.swing.border.EmptyBorder;

import net.sf.portecle.crypto.KeyPairType;
import net.sf.portecle.crypto.KeyPairUtil;

/**
 * Modal dialog that generates a key pair which the user may cancel at any time by pressing the cancel button.
 */
class DGeneratingKeyPair
    extends PortecleJDialog
{
	/** Whether the dialog was closed by a key pair worker */
	private boolean closedByWorker;

	/**
	 * Creates new DGeneratingKeyPair dialog.
	 * 
	 * @param parent The parent window
	 */
	public DGeneratingKeyPair(Window parent)
	{
		super(parent, true);
		initComponents();
	}

	/**
	 * Initialize the dialog's GUI components.
	 */
	private void initComponents()
	{
		// Generate key Pair label
		JLabel jlGenKeyPair = new JLabel(RB.getString("DGeneratingKeypair.jlGenKeyPair.text"));
		ImageIcon icon = new ImageIcon(getClass().getResource(RB.getString("DGeneratingKeypair.Generating.image")));
		jlGenKeyPair.setIcon(icon);
		JPanel jpGenKeyPair = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpGenKeyPair.add(jlGenKeyPair);
		jpGenKeyPair.setBorder(new EmptyBorder(5, 5, 5, 5));

		// Cancel button
		JButton jbCancel = getCancelButton();
		JPanel jpCancel = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpCancel.add(jbCancel);

		getContentPane().add(jpGenKeyPair, BorderLayout.NORTH);
		getContentPane().add(jpCancel, BorderLayout.SOUTH);

		setTitle(RB.getString("DGeneratingKeyPair.Title"));

		initDialog();
	}

	/**
	 * Get key pair worker.
	 * 
	 * @param keyPairType key pair type
	 * @param keySize key size
	 * @return Swing worker that creates a key pair
	 */
	public SwingWorker<KeyPair, Object> getKeyPairWorker(final KeyPairType keyPairType, final int keySize)
	{
		return new SwingWorker<KeyPair, Object>()
		{
			@Override
			protected KeyPair doInBackground()
		        throws Exception
			{
				return KeyPairUtil.generateKeyPair(keyPairType, keySize);
			}

			@Override
			protected void done()
			{
				closedByWorker = true;
				closeDialog();
				super.done();
			}
		};
	}

	/**
	 * Get whether the dialog was closed by a key pair worker.
	 * 
	 * @return True if the dialog was closed by a key pair worker, false otherwise
	 */
	public boolean isClosedByWorker()
	{
		return closedByWorker;
	}
}
