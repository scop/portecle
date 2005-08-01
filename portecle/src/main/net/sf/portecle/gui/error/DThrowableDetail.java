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
import java.util.Enumeration;
import java.util.ResourceBundle;

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
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

/**
 * Displays a throwable's stack trace.  Cause throwable's stack trace will be
 * show recursively also.
 */
public class DThrowableDetail extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/gui/error/resources");

    /** Panel to hold buttons */
    private JPanel m_jpButtons;

    /** Copy button to copy throwable stack traces to clipboard */
    private JButton m_jbCopy;

    /** OK button to dismiss dialog */
    private JButton m_jbOK;

    /** Panel to hold throwable stack traces */
    private JPanel m_jpThrowable;

    /** Tree to display throwable stack traces */
    private JTree m_jtrThrowable;

    /** Scroll pane to place throwable stack traces in */
    private JScrollPane m_jspThrowable;

    /** Stores throwable to display */
    private Throwable m_throwable;

    /**
     * Creates new DThrowableDetail dialog where the parent is a frame.
     *
     * @param parent Parent frame
     * @param bModal Is dialog modal?
     * @param throwable Throwable to display
     */
    public DThrowableDetail(JFrame parent, boolean bModal, Throwable throwable)
    {
        super(parent, bModal);
        m_throwable = throwable;
        initComponents();
    }

    /**
     * Creates new DThrowableDetail dialog where the parent is a dialog.
     *
     * @param parent Parent dialog
     * @param bModal Is dialog modal?
     * @param throwable Throwable to display
     */
    public DThrowableDetail(JDialog parent, boolean bModal,
                            Throwable throwable)
    {
        super(parent, bModal);
        m_throwable = throwable;
        initComponents();
    }

    /**
     * Initialise the dialog's GUI components.
     */
    private void initComponents()
    {
        // Buttons
        m_jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));

        m_jbOK = new JButton(m_res.getString("DThrowableDetail.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });
        m_jpButtons.add(m_jbOK);

        m_jbCopy = new JButton(
            m_res.getString("DThrowableDetail.m_jbCopy.text"));
        m_jbCopy.setMnemonic(
            m_res.getString("DThrowableDetail.m_jbCopy.mnemonic").charAt(0));
        m_jbCopy.setToolTipText(
            m_res.getString("DThrowableDetail.m_jbCopy.tooltip"));
        m_jbCopy.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                copyPressed();
            }
        });
        m_jpButtons.add(m_jbCopy);

        m_jpThrowable = new JPanel(new BorderLayout());
        m_jpThrowable.setBorder(new EmptyBorder(5, 5, 5, 5));

        // Load tree with info on throwable's stack trace
        m_jtrThrowable = new JTree(createThrowableNodes());
        // Top accomodate node icons with spare space (they are 16 pixels tall)
        m_jtrThrowable.setRowHeight(18);
        m_jtrThrowable.getSelectionModel().setSelectionMode(
            TreeSelectionModel.SINGLE_TREE_SELECTION);
        // Allow tooltips in tree
        ToolTipManager.sharedInstance().registerComponent(m_jtrThrowable);
        // Custom tree node renderer
        m_jtrThrowable.setCellRenderer(new ThrowableTreeCellRend());

        // Expand all nodes in tree
        /* ...then again, not.  Too much scary detail.
        TreeNode topNode = (TreeNode)m_jtrThrowable.getModel().getRoot();
        expandTree(m_jtrThrowable, new TreePath(topNode));
        */

        m_jspThrowable = new JScrollPane(
            m_jtrThrowable,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
            JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        m_jspThrowable.setPreferredSize(new Dimension(500, 250));
        m_jpThrowable.add(m_jspThrowable, BorderLayout.CENTER);

        getContentPane().add(m_jpThrowable, BorderLayout.CENTER);
        getContentPane().add(m_jpButtons, BorderLayout.SOUTH);

        setTitle(m_res.getString("DThrowableDetail.Title"));
        setResizable(true);

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        getRootPane().setDefaultButton(m_jbOK);

        pack();

        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                m_jbOK.requestFocus();
            }
        });
    }

    /**
     * Create tree node with information on the throwable and it's
     * cause throwables.
     *
     * @return The tree node
     */
    private DefaultMutableTreeNode createThrowableNodes()
    {
        // Top node
        DefaultMutableTreeNode topNode = new DefaultMutableTreeNode(
            m_res.getString("DThrowableDetail.RootNode.text"));

        Throwable throwable = m_throwable;

        while (throwable != null)
        {
            // Create a node for each throwable in cause chain and add
            // as a child to the top node
            DefaultMutableTreeNode throwableNode =
                new DefaultMutableTreeNode(throwable);
            topNode.add(throwableNode);

            StackTraceElement[] stackTrace = throwable.getStackTrace();

            for (int iCnt=0; iCnt < stackTrace.length; iCnt++)
            {
                // Create a node for each stack trace entry and add it
                // to the throwable node
                throwableNode.add(
                    new DefaultMutableTreeNode(stackTrace[iCnt]));
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
    private void expandTree(JTree tree, TreePath parent)
    {
        // Traverse children expending nodes
        TreeNode node = (TreeNode) parent.getLastPathComponent();
        if (node.getChildCount() >= 0)
        {
            for (Enumeration en = node.children(); en.hasMoreElements();)
            {
                TreeNode subNode = (TreeNode) en.nextElement();
                TreePath path = parent.pathByAddingChild(subNode);
                expandTree(tree, path);
            }
        }

        tree.expandPath(parent);
    }

    /**
     * Copy button pressed - copy throwable stack traces to clipboard.
     */
    private void copyPressed()
    {
        // Put provider information in here
        StringBuffer strBuff = new StringBuffer();

        Throwable throwable = m_throwable;

        while (throwable != null)
        {
            strBuff.append(throwable);
            strBuff.append('\n');

            StackTraceElement[] stackTrace = throwable.getStackTrace();

            for (int iCnt=0; iCnt < stackTrace.length; iCnt++)
            {
                strBuff.append('\t');
                strBuff.append(stackTrace[iCnt]);
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

    /**
     * OK button pressed or otherwise activated.
     */
    private void okPressed()
    {
        closeDialog();
    }

    /**
     * Hides the Throwable Detail dialog.
     */
    private void closeDialog()
    {
        setVisible(false);
        dispose();
    }
}
