/*
 * DGeneratingKeyPair.java
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
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.KeyPair;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

import net.sf.portecle.crypto.CryptoException;
import net.sf.portecle.crypto.KeyPairType;
import net.sf.portecle.crypto.KeyPairUtil;
import net.sf.portecle.gui.error.DThrowable;

/**
 * Generates a key pair which the user may cancel at any time by pressing the cancel button.
 */
class DGeneratingKeyPair
    extends JDialog
{
	/** Key from input map to action map for the cancel button */
	private static final String CANCEL_KEY = "CANCEL_KEY";

	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

	/** Stores the key pair generation type */
	private KeyPairType m_keyPairType;

	/** Stores the key pair size to generate */
	private int m_iKeySize;

	/** Generated key pair */
	private KeyPair m_keyPair;

	/**
	 * Reference to the dialog for the GenerateKeyPair inner class to reference
	 */
	private JDialog dialog = this;

	/** The thread that actually does the key pair generation */
	private Thread m_generator;

	/**
	 * Creates new DGeneratingKeyPair dialog where the parent is a frame.
	 * 
	 * @param parent The parent frame
	 * @param bModal Is dialog modal?
	 * @param keyPairType The key pair generation type
	 * @param iKeySize The key size to generate
	 */
	public DGeneratingKeyPair(JFrame parent, boolean bModal, KeyPairType keyPairType, int iKeySize)
	{
		super(parent, bModal);
		m_keyPairType = keyPairType;
		m_iKeySize = iKeySize;
		initComponents();
	}

	/**
	 * Creates new DGeneratingKeyPair dialog where the parent is a dialog.
	 * 
	 * @param parent The parent dialog
	 * @param bModal Is dialog modal?
	 * @param keyPairType The key pair generation type
	 * @param iKeySize The key size to generate
	 */
	public DGeneratingKeyPair(JDialog parent, boolean bModal, KeyPairType keyPairType, int iKeySize)
	{
		super(parent, bModal);
		m_keyPairType = keyPairType;
		m_iKeySize = iKeySize;
		initComponents();
	}

	/**
	 * Initialise the dialog's GUI components.
	 */
	private void initComponents()
	{
		// Generate key Pair label
		JLabel jlGenKeyPair = new JLabel(m_res.getString("DGeneratingKeypair.jlGenKeyPair.text"));
		ImageIcon icon =
		    new ImageIcon(getClass().getResource(m_res.getString("DGeneratingKeypair.Generating.image")));
		jlGenKeyPair.setIcon(icon);
		JPanel jpGenKeyPair = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpGenKeyPair.add(jlGenKeyPair);
		jpGenKeyPair.setBorder(new EmptyBorder(5, 5, 5, 5));

		// Cancel button
		JButton jbCancel = new JButton(m_res.getString("DGeneratingKeyPair.jbCancel.text"));
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
		JPanel jpCancel = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpCancel.add(jbCancel);

		getContentPane().add(jpGenKeyPair, BorderLayout.NORTH);
		getContentPane().add(jpCancel, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter()
		{
			@Override
			public void windowClosing(WindowEvent evt)
			{
				if (m_generator != null && m_generator.isAlive())
				{
					m_generator.interrupt();
				}
				closeDialog();
			}
		});

		setTitle(m_res.getString("DGeneratingKeyPair.Title"));
		setResizable(false);

		pack();
	}

	/**
	 * Start key pair generation in a separate thread.
	 */
	public void startKeyPairGeneration()
	{
		m_generator = new Thread(new GenerateKeyPair());
		m_generator.setPriority(Thread.MIN_PRIORITY);
		m_generator.start();
	}

	/**
	 * Cancel button pressed or otherwise activated.
	 */
	private void cancelPressed()
	{
		if (m_generator != null && m_generator.isAlive())
		{
			m_generator.interrupt();
		}
		closeDialog();
	}

	/** Closes the dialog */
	private void closeDialog()
	{
		setVisible(false);
		dispose();
	}

	/**
	 * Get the generated key pair.
	 * 
	 * @return The generated key pair or null if the user cancelled the dialog
	 */
	public KeyPair getKeyPair()
	{
		return m_keyPair;
	}

	/**
	 * Generates a key pair. Is Runnable so can be run in a separate thread.
	 */
	private class GenerateKeyPair
	    implements Runnable
	{
		/** Store any crypto exception that occurs */
		CryptoException m_ex;

		/**
		 * Generate a key pair.
		 */
		public void run()
		{
			// Generate key pair
			KeyPair keyPair;
			try
			{
				keyPair = KeyPairUtil.generateKeyPair(m_keyPairType, m_iKeySize);

				// @@@ TODO what's this?
				if (true)

					m_keyPair = keyPair;

				// Manipulate GUI in event handler thread
				SwingUtilities.invokeLater(new Runnable()
				{
					public void run()
					{
						if (dialog.isShowing())
						{
							closeDialog();
						}
					}
				});
			}
			catch (CryptoException ex)
			{
				// Store exception in member so it can be accessed
				// from inner class
				m_ex = ex;

				// Manipulate GUI in event handler thread
				SwingUtilities.invokeLater(new Runnable()
				{
					public void run()
					{
						if (dialog.isShowing())
						{
							DThrowable dThrowable = new DThrowable(dialog, null, true, m_ex);
							dThrowable.setLocationRelativeTo(DGeneratingKeyPair.this);
							dThrowable.setVisible(true);
							closeDialog();
						}
					}
				});
			}
		}
	}
}
