/*
 * DGetHostPort.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004-2008 Ville Skyttä, ville.skytta@iki.fi
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
import java.net.InetSocketAddress;
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

import net.sf.portecle.gui.error.DThrowable;

/**
 * Dialog used for entering an IP address and a port.
 */
class DGetHostPort
    extends JDialog
{
	/** Key from input map to action map for the cancel button */
	private static final String CANCEL_KEY = "CANCEL_KEY";

	/** Default port */
	private static final int DEFAULT_PORT = 443;

	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

	/** Host text field */
	private JTextField m_jtfHost;

	/** Port text field */
	private JTextField m_jtfPort;

	/** Stores the address entered by the user */
	private InetSocketAddress m_iAddress;

	/**
	 * Creates new DGetHostPort dialog.
	 * 
	 * @param parent The parent window
	 * @param sTitle The dialog's title
	 * @param modal Is the dialog modal?
	 * @param iOldHostPort The address to display initially
	 */
	public DGetHostPort(Window parent, String sTitle, boolean modal, InetSocketAddress iOldHostPort)
	{
		super(parent, sTitle, (modal ? Dialog.DEFAULT_MODALITY_TYPE : Dialog.ModalityType.MODELESS));
		initComponents(iOldHostPort);
	}

	/**
	 * Get the host+port entered by the user.
	 * 
	 * @return The host+port, or null if none was entered
	 */
	public InetSocketAddress getHostPort()
	{
		return m_iAddress;
	}

	/**
	 * Initialise the dialog's GUI components.
	 * 
	 * @param iOldHostPort The host+port to display initially
	 */
	private void initComponents(InetSocketAddress iOldHostPort)
	{
		getContentPane().setLayout(new BorderLayout());

		JLabel jlHost = new JLabel(m_res.getString("DGetHostPort.jlHost.text"));
		m_jtfHost = new JTextField(15);

		JLabel jlPort = new JLabel(m_res.getString("DGetHostPort.jlPort.text"));
		m_jtfPort = new JTextField(5);

		if (iOldHostPort != null)
		{
			m_jtfHost.setText(iOldHostPort.getHostName());
			m_jtfHost.setCaretPosition(0);
			m_jtfPort.setText(String.valueOf(iOldHostPort.getPort()));
		}
		else
		{
			m_jtfPort.setText(String.valueOf(DEFAULT_PORT));
		}
		m_jtfPort.setCaretPosition(0);

		JButton jbOK = new JButton(m_res.getString("DGetHostPort.jbOK.text"));
		jbOK.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				okPressed();
			}
		});

		JButton jbCancel = new JButton(m_res.getString("DGetHostPort.jbCancel.text"));
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

		JPanel jpHostPort = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpHostPort.add(jlHost);
		jpHostPort.add(m_jtfHost);
		jpHostPort.add(jlPort);
		jpHostPort.add(m_jtfPort);
		jpHostPort.setBorder(new EmptyBorder(5, 5, 5, 5));

		JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpButtons.add(jbOK);
		jpButtons.add(jbCancel);

		getContentPane().add(jpHostPort, BorderLayout.CENTER);
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
	}

	/**
	 * Check that the host+port entered is valid.
	 * 
	 * @return True if the host+port is valid, false otherwise
	 */
	private boolean checkHostPort()
	{
		String sHost = m_jtfHost.getText().trim().toLowerCase();
		if (sHost.length() > 0)
		{
			sHost = m_jtfHost.getText().trim();
		}
		else
		{
			JOptionPane.showMessageDialog(this, m_res.getString("DGetHostPort.HostReq.message"), getTitle(),
			    JOptionPane.WARNING_MESSAGE);
			return false;
		}

		String sPort = m_jtfPort.getText().trim().toLowerCase();
		if (sPort.length() > 0)
		{
			sPort = m_jtfPort.getText().trim();
		}
		else
		{
			JOptionPane.showMessageDialog(this, m_res.getString("DGetHostPort.PortReq.message"), getTitle(),
			    JOptionPane.WARNING_MESSAGE);
			return false;
		}
		int port;
		try
		{
			port = Integer.parseInt(sPort);
		}
		catch (Exception e)
		{
			DThrowable.showAndWait(this, null, e);
			return false;
		}

		try
		{
			m_iAddress = new InetSocketAddress(sHost, port);
		}
		catch (Exception e)
		{
			DThrowable.showAndWait(this, null, e);
			return false;
		}

		return true;
	}

	/**
	 * OK button pressed or otherwise activated.
	 */
	private void okPressed()
	{
		if (checkHostPort())
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
