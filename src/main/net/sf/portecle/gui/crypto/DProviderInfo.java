/*
 * DProviderInfo.java
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

package net.sf.portecle.gui.crypto;

import static net.sf.portecle.FPortecle.RB;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.Provider;
import java.security.Security;
import java.text.MessageFormat;
import java.util.TreeSet;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.ScrollPaneConstants;
import javax.swing.ToolTipManager;
import javax.swing.border.EmptyBorder;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeSelectionModel;

import net.sf.portecle.PortecleJDialog;

/**
 * Modal dialog to display information on the currently loaded security providers.
 */
public class DProviderInfo
    extends PortecleJDialog
{
	/**
	 * Creates new DProviderInfo dialog.
	 * 
	 * @param parent Parent window
	 */
	public DProviderInfo(Window parent)
	{
		super(parent, true);
		initComponents();
	}

	/**
	 * Initialize the dialog's GUI components.
	 */
	private void initComponents()
	{
		// Buttons
		JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));

		JButton jbOK = getOkButton(true);
		jpButtons.add(jbOK);

		JButton jbCopy = new JButton(RB.getString("DProviderInfo.jbCopy.text"));
		jbCopy.setMnemonic(RB.getString("DProviderInfo.jbCopy.mnemonic").charAt(0));
		jbCopy.setToolTipText(RB.getString("DProviderInfo.jbCopy.tooltip"));
		jbCopy.addActionListener(new ActionListener()
		{
			@Override
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
		// Top accommodate node icons with spare space (they are 16 pixels tall)
		jtrProviders.setRowHeight(18);
		jtrProviders.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		// Allow tool tips in tree
		ToolTipManager.sharedInstance().registerComponent(jtrProviders);
		// Custom tree node renderer
		jtrProviders.setCellRenderer(new ProviderTreeCellRend());

		JScrollPane jspProviders = new JScrollPane(jtrProviders, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
		    ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
		jspProviders.setPreferredSize(new Dimension(350, 200));
		jpProviders.add(jspProviders, BorderLayout.CENTER);

		getContentPane().add(jpProviders, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		setTitle(RB.getString("DProviderInfo.Title"));

		getRootPane().setDefaultButton(jbOK);

		initDialog();

		setResizable(true);
		jbOK.requestFocusInWindow();
	}

	/**
	 * Create tree node with information on all loaded providers.
	 * 
	 * @return The tree node
	 */
	private DefaultMutableTreeNode createProviderNodes()
	{
		// Top node
		DefaultMutableTreeNode topNode = new DefaultMutableTreeNode(RB.getString("DProviderInfo.TopNodeName"));

		// For each provider...
		for (Provider provider : Security.getProviders())
		{
			// Create a node with the provider name and add it as a child of the top node
			DefaultMutableTreeNode providerNode = new DefaultMutableTreeNode(provider.getName());
			topNode.add(providerNode);

			// Add child nodes to the provider node for provider description and version
			providerNode.add(new DefaultMutableTreeNode(provider.getInfo()));
			providerNode.add(new DefaultMutableTreeNode("" + provider.getVersion()));

			// Create another child node called properties and...
			DefaultMutableTreeNode providerPropertiesNode =
			    new DefaultMutableTreeNode(RB.getString("DProviderInfo.ProviderProperties"));
			providerNode.add(providerPropertiesNode);

			// ...add property child nodes to it. Use a TreeSet for sorting the properties.
			for (Object o : new TreeSet<>(provider.keySet()))
			{
				String sKey = String.valueOf(o);
				String sValue = provider.getProperty(sKey);
				providerPropertiesNode.add(new DefaultMutableTreeNode(
				    MessageFormat.format(RB.getString("DProviderInfo.ProviderProperty"), sKey, sValue)));
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

		// For each provider...
		for (Provider provider : Security.getProviders())
		{
			if (strBuff.length() != 0)
			{
				strBuff.append('\n');
			}

			// ...write out the provider name, description and version...
			strBuff.append(MessageFormat.format(RB.getString("DProviderInfo.Copy.ProviderName"), provider.getName()));
			strBuff.append('\n');
			strBuff.append(
			    MessageFormat.format(RB.getString("DProviderInfo.Copy.ProviderVersion"), provider.getVersion()));
			strBuff.append('\n');
			strBuff.append(
			    MessageFormat.format(RB.getString("DProviderInfo.Copy.ProviderDescription"), provider.getInfo()));
			strBuff.append('\n');
			strBuff.append(RB.getString("DProviderInfo.Copy.ProviderProperties"));
			strBuff.append('\n');

			// ...and it's properties. Use a TreeSet for sorting the properties.
			for (Object o : new TreeSet<>(provider.keySet()))
			{
				String sKey = String.valueOf(o);
				String sValue = provider.getProperty(sKey);
				strBuff.append('\t');
				strBuff.append(sKey);
				strBuff.append('=');
				strBuff.append(sValue);
				strBuff.append('\n');
			}
		}

		// Copy to clipboard
		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		StringSelection copy = new StringSelection(strBuff.toString());
		clipboard.setContents(copy, copy);
	}
}
