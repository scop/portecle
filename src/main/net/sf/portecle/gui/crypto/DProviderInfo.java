/*
 * DProviderInfo.java
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

package net.sf.portecle.gui.crypto;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.Provider;
import java.security.Security;
import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.TreeSet;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.ToolTipManager;
import javax.swing.border.EmptyBorder;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeSelectionModel;

/**
 * Displays information on the currently loaded security providers.
 */
public class DProviderInfo
    extends JDialog
{
	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/gui/crypto/resources");

	/**
	 * Creates new DProviderInfo dialog where the parent is a frame.
	 * 
	 * @param parent Parent frame
	 * @param bModal Is dialog modal?
	 */
	public DProviderInfo(JFrame parent, boolean bModal)
	{
		super(parent, bModal);
		initComponents();
	}

	/**
	 * Creates new DProviderInfo dialog where the parent is a dialog.
	 * 
	 * @param parent Parent dialog
	 * @param bModal Is dialog modal?
	 */
	public DProviderInfo(JDialog parent, boolean bModal)
	{
		super(parent, bModal);
		initComponents();
	}

	/**
	 * Initialise the dialog's GUI components.
	 */
	private void initComponents()
	{
		// Buttons
		JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));

		final JButton jbOK = new JButton(m_res.getString("DProviderInfo.jbOK.text"));
		jbOK.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				okPressed();
			}
		});

		jpButtons.add(jbOK);

		JButton jbCopy = new JButton(m_res.getString("DProviderInfo.jbCopy.text"));
		jbCopy.setMnemonic(m_res.getString("DProviderInfo.jbCopy.mnemonic").charAt(0));
		jbCopy.setToolTipText(m_res.getString("DProviderInfo.jbCopy.tooltip"));
		jbCopy.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				copyPressed();
			}
		});

		jpButtons.add(jbCopy);

		JPanel jpProviders = new JPanel(new BorderLayout());
		jpProviders.setBorder(new EmptyBorder(5, 5, 5, 5));

		// Load tree with info on loaded security providers
		JTree jtrProviders = new JTree(createProviderNodes());
		// Top accomodate node icons with spare space (they are 16 pixels tall)
		jtrProviders.setRowHeight(18);
		jtrProviders.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		// Allow tooltips in tree
		ToolTipManager.sharedInstance().registerComponent(jtrProviders);
		// Custom tree node renderer
		jtrProviders.setCellRenderer(new ProviderTreeCellRend());

		JScrollPane jspProviders =
		    new JScrollPane(jtrProviders, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
		        JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
		jspProviders.setPreferredSize(new Dimension(350, 200));
		jpProviders.add(jspProviders, BorderLayout.CENTER);

		getContentPane().add(jpProviders, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		setTitle(m_res.getString("DProviderInfo.Title"));
		setResizable(true);

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

		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				jbOK.requestFocus();
			}
		});
	}

	/**
	 * Create tree node with information on all loaded providers.
	 * 
	 * @return The tree node
	 */
	private DefaultMutableTreeNode createProviderNodes()
	{
		// Top node
		DefaultMutableTreeNode topNode =
		    new DefaultMutableTreeNode(m_res.getString("DProviderInfo.TopNodeName"));

		// Get security providers
		Provider[] providers = Security.getProviders();

		// For each provider...
		for (int iCnt = 0; iCnt < providers.length; iCnt++)
		{
			Provider provider = providers[iCnt];

			// Create a node with the provider name and add it as a
			// child of the top node
			DefaultMutableTreeNode providerNode = new DefaultMutableTreeNode(provider.getName());
			topNode.add(providerNode);

			// Add child nodes to the provider node for provider
			// decription and version
			providerNode.add(new DefaultMutableTreeNode(provider.getInfo()));
			providerNode.add(new DefaultMutableTreeNode("" + provider.getVersion()));

			// Create another child node called properties and...
			DefaultMutableTreeNode providerPropertiesNode =
			    new DefaultMutableTreeNode(m_res.getString("DProviderInfo.ProviderProperties"));
			providerNode.add(providerPropertiesNode);

			// ...add property child nodes to it.
			// Use a TreeSet for sorting the properties.
			for (Object o : new TreeSet<Object>(provider.keySet()))
			{
				String sKey = String.valueOf(o);
				String sValue = provider.getProperty(sKey);
				providerPropertiesNode.add(new DefaultMutableTreeNode(MessageFormat.format(
				    m_res.getString("DProviderInfo.ProviderProperty"), sKey, sValue)));
			}
		}

		return topNode;
	}

	/**
	 * Copy button pressed - copy provider information to clipboard.
	 */
	private void copyPressed()
	{
		// Put provider information in here
		StringBuilder strBuff = new StringBuilder();

		// Get security providers
		Provider[] providers = Security.getProviders();

		// For each provider...
		for (int iCnt = 0; iCnt < providers.length; iCnt++)
		{
			Provider provider = providers[iCnt];

			// ...write out the provider name, description and version...
			strBuff.append(MessageFormat.format(m_res.getString("DProviderInfo.Copy.ProviderName"),
			    provider.getName()));
			strBuff.append('\n');
			strBuff.append(MessageFormat.format(m_res.getString("DProviderInfo.Copy.ProviderVersion"),
			    provider.getVersion()));
			strBuff.append('\n');
			strBuff.append(MessageFormat.format(m_res.getString("DProviderInfo.Copy.ProviderDescription"),
			    provider.getInfo()));
			strBuff.append('\n');
			strBuff.append(m_res.getString("DProviderInfo.Copy.ProviderProperties"));
			strBuff.append('\n');

			// ...and it's properties
			// Use a TreeSet for sorting the properties.
			for (Object o : new TreeSet<Object>(provider.keySet()))
			{
				String sKey = String.valueOf(o);
				String sValue = provider.getProperty(sKey);
				strBuff.append('\t');
				strBuff.append(sKey);
				strBuff.append('=');
				strBuff.append(sValue);
				strBuff.append('\n');
			}

			if (iCnt + 1 < providers.length)
			{
				strBuff.append('\n');
			}
		}

		// Copy to clipboard
		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		StringSelection copy = new StringSelection(strBuff.toString());
		clipboard.setContents(copy, copy);
	}

	/**
	 * OK button pressed or otherwise activated.
	 */
	private void okPressed()
	{
		closeDialog();
	}

	/**
	 * Hides the dialog.
	 */
	private void closeDialog()
	{
		setVisible(false);
		dispose();
	}
}
