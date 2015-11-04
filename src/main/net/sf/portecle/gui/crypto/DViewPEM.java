/*
 * DViewPEM.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2006-2014 Ville Skyttä, ville.skytta@iki.fi
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

package net.sf.portecle.gui.crypto;

import static net.sf.portecle.FPortecle.RB;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.text.MessageFormat;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.EmptyBorder;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import net.sf.portecle.PortecleJDialog;
import net.sf.portecle.crypto.CryptoException;
import net.sf.portecle.gui.error.DThrowable;

/**
 * Modal dialog to display an X.509 object's PEM encoding.
 */
public class DViewPEM
    extends PortecleJDialog
{
	/** Stores object to display */
	private final Object m_object;

	/** Stores PEM encoding */
	private String m_pem;

	/** File chooser for saving the PEM encoded object */
	private final JFileChooser m_chooser;

	/**
	 * Creates new DViewPEM dialog.
	 * 
	 * @param parent Parent window
	 * @param sTitle The dialog title
	 * @param obj Object to display encoding for
	 * @param chooser File chooser for saving the PEM encoding
	 * @throws CryptoException A problem was encountered getting the object's PEM encoding
	 */
	public DViewPEM(Window parent, String sTitle, Object obj, JFileChooser chooser)
	    throws CryptoException
	{
		super(parent, sTitle, true);
		m_object = obj;
		m_chooser = chooser;
		initComponents();
	}

	/**
	 * Initialize the dialog's GUI components.
	 * 
	 * @throws CryptoException A problem was encountered getting the object's PEM encoding
	 */
	private void initComponents()
	    throws CryptoException
	{
		if (m_pem == null)
		{
			StringWriter encoded = new StringWriter();
			try (JcaPEMWriter pw = new JcaPEMWriter(encoded))
			{
				pw.writeObject(m_object);
			}
			catch (IOException e)
			{
				throw new CryptoException(RB.getString("DViewPEM.exception.message"), e);
			}
			m_pem = encoded.toString();
		}

		JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));

		JButton jbOK = getOkButton(true);

		final JButton jbSave = new JButton(RB.getString("DViewPEM.jbSave.text"));
		jbSave.setMnemonic(RB.getString("DViewPEM.jbSave.mnemonic").charAt(0));
		if (m_chooser == null || m_pem == null)
		{
			jbSave.setEnabled(false);
		}
		else
		{
			jbSave.addActionListener(new ActionListener()
			{
				@Override
				public void actionPerformed(ActionEvent evt)
				{
					savePressed();
				}
			});
		}

		jpButtons.add(jbOK);
		jpButtons.add(jbSave);

		JPanel jpPEM = new JPanel(new BorderLayout());
		jpPEM.setBorder(new EmptyBorder(5, 5, 5, 5));

		// Load text area with the PEM encoding
		JTextArea jtaPEM = new JTextArea(m_pem);
		jtaPEM.setCaretPosition(0);
		jtaPEM.setEditable(false);
		jtaPEM.setFont(new Font(Font.MONOSPACED, Font.PLAIN, jtaPEM.getFont().getSize()));

		JScrollPane jspPEM = new JScrollPane(jtaPEM, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
		    ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
		jspPEM.setPreferredSize(new Dimension(500, 300));
		jpPEM.add(jspPEM, BorderLayout.CENTER);

		getContentPane().add(jpPEM, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		getRootPane().setDefaultButton(jbOK);

		initDialog();

		setResizable(true);
		jbOK.requestFocusInWindow();
	}

	/**
	 * Save button pressed or otherwise activated.
	 */
	private void savePressed()
	{
		int iRtnValue = m_chooser.showDialog(this, RB.getString("DViewPEM.jbSave.text"));
		if (iRtnValue == JFileChooser.APPROVE_OPTION)
		{
			File fExportFile = m_chooser.getSelectedFile();

			if (fExportFile.isFile())
			{
				String sMessage =
				    MessageFormat.format(RB.getString("DViewPEM.OverWriteFile.message"), fExportFile.getName());
				int iSelected = JOptionPane.showConfirmDialog(this, sMessage, getTitle(), JOptionPane.YES_NO_OPTION);
				if (iSelected == JOptionPane.NO_OPTION)
					return;
			}

			try (FileWriter fw = new FileWriter(fExportFile))
			{
				fw.write(m_pem);
			}
			catch (FileNotFoundException ex)
			{
				String sMessage =
				    MessageFormat.format(RB.getString("DViewPEM.NoWriteFile.message"), fExportFile.getName());
				JOptionPane.showMessageDialog(this, sMessage, getTitle(), JOptionPane.WARNING_MESSAGE);
			}
			catch (IOException e)
			{
				DThrowable.showAndWait(this, null, e);
			}
		}
	}
}
