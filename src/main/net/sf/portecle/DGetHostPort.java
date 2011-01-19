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

import static net.sf.portecle.FPortecle.RB;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Window;
import java.net.InetSocketAddress;
import java.util.Locale;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import javax.swing.text.AbstractDocument;
import javax.swing.text.Document;

import net.sf.portecle.gui.IntegerDocumentFilter;
import net.sf.portecle.gui.SwingHelper;
import net.sf.portecle.gui.error.DThrowable;

/**
 * Modal dialog used for entering an IP address and a port.
 */
class DGetHostPort
    extends PortecleJDialog
{
	/** Default port */
	// TODO: move to resources
	private static final String DEFAULT_PORT = "443";

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
	 * @param iOldHostPort The address to display initially
	 */
	public DGetHostPort(Window parent, String sTitle, InetSocketAddress iOldHostPort)
	{
		super(parent, sTitle, true);
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
	 * Initialize the dialog's GUI components.
	 * 
	 * @param iOldHostPort The host+port to display initially
	 */
	private void initComponents(InetSocketAddress iOldHostPort)
	{
		getContentPane().setLayout(new BorderLayout());

		JLabel jlHost = new JLabel(RB.getString("DGetHostPort.jlHost.text"));
		m_jtfHost = new JTextField(15);
		jlHost.setLabelFor(m_jtfHost);

		JLabel jlPort = new JLabel(RB.getString("DGetHostPort.jlPort.text"));
		m_jtfPort = new JTextField(DEFAULT_PORT, 5);
		Document doc = m_jtfPort.getDocument();
		if (doc instanceof AbstractDocument)
		{
			((AbstractDocument) doc).setDocumentFilter(new IntegerDocumentFilter(m_jtfPort.getColumns()));
		}
		if (iOldHostPort != null)
		{
			m_jtfHost.setText(iOldHostPort.getHostName());
			m_jtfPort.setText(String.valueOf(iOldHostPort.getPort()));
		}
		jlPort.setLabelFor(m_jtfPort);

		JPanel jpHostPort = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpHostPort.add(jlHost);
		jpHostPort.add(m_jtfHost);
		jpHostPort.add(jlPort);
		jpHostPort.add(m_jtfPort);
		jpHostPort.setBorder(new EmptyBorder(5, 5, 5, 5));

		JButton jbOK = getOkButton(false);
		JButton jbCancel = getCancelButton();

		JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpButtons.add(jbOK);
		jpButtons.add(jbCancel);

		getContentPane().add(jpHostPort, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		getRootPane().setDefaultButton(jbOK);

		initDialog();
	}

	/**
	 * Check that the host+port entered is valid.
	 * 
	 * @return True if the host+port is valid, false otherwise
	 */
	private boolean checkHostPort()
	{
		String sHost = m_jtfHost.getText().trim().toLowerCase(Locale.ENGLISH);
		if (sHost.isEmpty())
		{
			JOptionPane.showMessageDialog(this, RB.getString("DGetHostPort.HostReq.message"), getTitle(),
			    JOptionPane.WARNING_MESSAGE);
			SwingHelper.selectAndFocus(m_jtfHost);
			return false;
		}

		String sPort = m_jtfPort.getText().trim();
		if (sPort.isEmpty())
		{
			JOptionPane.showMessageDialog(this, RB.getString("DGetHostPort.PortReq.message"), getTitle(),
			    JOptionPane.WARNING_MESSAGE);
			SwingHelper.selectAndFocus(m_jtfPort);
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
			SwingHelper.selectAndFocus(m_jtfPort);
			return false;
		}

		try
		{
			m_iAddress = new InetSocketAddress(sHost, port);
		}
		catch (Exception e)
		{
			DThrowable.showAndWait(this, null, e);
			// Most likely port out of range...
			SwingHelper.selectAndFocus(m_jtfPort);
			return false;
		}

		return true;
	}

	/**
	 * OK button pressed or otherwise activated.
	 */
	@Override
	protected void okPressed()
	{
		if (checkHostPort())
		{
			super.okPressed();
		}
	}
}
