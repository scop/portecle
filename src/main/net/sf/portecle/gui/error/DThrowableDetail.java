/*
 * DThrowableDetail.java
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

package net.sf.portecle.gui.error;

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
 * Modal dialog to display a throwable's stack trace. Cause throwable's stack trace will be show recursively also.
 */
/* package private */class DThrowableDetail
    extends PortecleJDialog
{
	/** Stores throwable to display */
	private final Throwable m_throwable;

	/**
	 * Creates new DThrowableDetail dialog.
	 * 
	 * @param parent Parent window
	 * @param throwable Throwable to display
	 */
	public DThrowableDetail(Window parent, Throwable throwable)
	{
		super(parent, true);
		m_throwable = throwable;
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

		JButton jbCopy = new JButton(RB.getString("DThrowableDetail.jbCopy.text"));
		jbCopy.setMnemonic(RB.getString("DThrowableDetail.jbCopy.mnemonic").charAt(0));
		jbCopy.setToolTipText(RB.getString("DThrowableDetail.jbCopy.tooltip"));
		jbCopy.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent evt)
			{
				copyPressed();
			}
		});
		jpButtons.add(jbCopy);

		JPanel jpThrowable = new JPanel(new BorderLayout());
		jpThrowable.setBorder(new EmptyBorder(5, 5, 5, 5));

		// Load tree with info on throwable's stack trace
		JTree jtrThrowable = new JTree(createThrowableNodes());
		// Top accommodate node icons with spare space (they are 16 pixels tall)
		jtrThrowable.setRowHeight(18);
		jtrThrowable.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		// Allow tool tips in tree
		ToolTipManager.sharedInstance().registerComponent(jtrThrowable);
		// Custom tree node renderer
		jtrThrowable.setCellRenderer(new ThrowableTreeCellRend());

		// Expand all nodes in tree
		/*
		 * ...then again, not. Too much scary detail. TreeNode topNode = (TreeNode)jtrThrowable.getModel().getRoot();
		 * expandTree(jtrThrowable, new TreePath(topNode));
		 */

		JScrollPane jspThrowable = new JScrollPane(jtrThrowable, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
		    ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
		jspThrowable.setPreferredSize(new Dimension(500, 250));
		jpThrowable.add(jspThrowable, BorderLayout.CENTER);

		getContentPane().add(jpThrowable, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		setTitle(RB.getString("DThrowableDetail.Title"));

		getRootPane().setDefaultButton(jbOK);

		initDialog();

		setResizable(true);
		jbOK.requestFocusInWindow();
	}

	/**
	 * Create tree node with information on the throwable and its cause throwables.
	 * 
	 * @return The tree node
	 */
	private DefaultMutableTreeNode createThrowableNodes()
	{
		// Top node
		DefaultMutableTreeNode topNode = new DefaultMutableTreeNode(RB.getString("DThrowableDetail.RootNode.text"));

		Throwable throwable = m_throwable;

		while (throwable != null)
		{
			// Create a node for each throwable in cause chain and add
			// as a child to the top node
			DefaultMutableTreeNode throwableNode = new DefaultMutableTreeNode(throwable);
			topNode.add(throwableNode);

			for (StackTraceElement ste : throwable.getStackTrace())
			{
				// Create a node for each stack trace entry and add it
				// to the throwable node
				throwableNode.add(new DefaultMutableTreeNode(ste));
			}

			throwable = throwable.getCause();
		}

		return topNode;
	}

	/**
	 * Expand node and all sub-nodes in a JTree.
	 * 
	 * @param tree The tree.
	 * @param parent Path to node to expand
	 */
	/*
	 * private void expandTree(JTree tree, TreePath parent) { // Traverse children expending nodes TreeNode node =
	 * (TreeNode) parent.getLastPathComponent(); if (node.getChildCount() >= 0) { for (Enumeration en = node.children();
	 * en.hasMoreElements();) { TreeNode subNode = (TreeNode) en.nextElement(); TreePath path =
	 * parent.pathByAddingChild(subNode); expandTree(tree, path); } } tree.expandPath(parent); }
	 */

	/**
	 * Copy button pressed - copy throwable stack traces to clipboard.
	 */
	private void copyPressed()
	{
		// Put provider information in here
		StringBuilder strBuff = new StringBuilder();

		Throwable throwable = m_throwable;

		while (throwable != null)
		{
			strBuff.append(throwable);
			strBuff.append('\n');

			for (StackTraceElement ste : throwable.getStackTrace())
			{
				strBuff.append('\t');
				strBuff.append(ste);
				strBuff.append('\n');
			}

			throwable = throwable.getCause();

			if (throwable != null)
			{
				strBuff.append('\n');
			}
		}

		// Copy to clipboard
		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		StringSelection copy = new StringSelection(strBuff.toString());
		clipboard.setContents(copy, copy);
	}
}
