/*
 * DProviderInfo.java
 *
 * Copyright (C) 2004 Wayne Grant
 * waynedgrant@hotmail.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * (This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

package net.sf.portecle.gui.crypto;

import java.io.*;
import java.util.*;
import java.text.MessageFormat;
import java.security.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.event.*;
import java.awt.datatransfer.*;

/**
 * Displays information on the currently loaded security providers.
 */
public class DProviderInfo extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/gui/crypto/resources");

    /** Panel to hold buttons */
    private JPanel m_jpButtons;

    /** Copy button to copy provider information to clipboard */
    private JButton m_jbCopy;

    /** OK button to dismiss dialog */
    private JButton m_jbOK;

    /** Panel to hold security providers tree */
    private JPanel m_jpProviders;

    /** Tree to display security providers  */
    private JTree m_jtrProviders;

    /** Scroll pane to place security providers tree in */
    private JScrollPane m_jspProviders;

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
        m_jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));

        m_jbCopy = new JButton(m_res.getString("DProviderInfo.m_jbCopy.text"));
        m_jbCopy.setMnemonic(m_res.getString("DProviderInfo.m_jbCopy.mnemonic").charAt(0));
        m_jbCopy.setToolTipText(m_res.getString("DProviderInfo.m_jbCopy.tooltip"));
        m_jbCopy.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                copyPressed();
            }
        });

        m_jpButtons.add(m_jbCopy);

        m_jbOK = new JButton(m_res.getString("DProviderInfo.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        m_jpButtons.add(m_jbOK);

        m_jpProviders = new JPanel(new BorderLayout());
        m_jpProviders.setBorder(new EmptyBorder(5, 5, 5, 5));

        // Load tree with info on loaded security providers
        m_jtrProviders = new JTree(createProviderNodes());
        m_jtrProviders.setRowHeight(18); // Top accomodate node icons with spare space (they are 16 pixels tall)
        m_jtrProviders.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        ToolTipManager.sharedInstance().registerComponent(m_jtrProviders); // Allow tooltips in tree
        m_jtrProviders.setCellRenderer(new ProviderTreeCellRend()); // Custom tree node renderer

        m_jspProviders = new JScrollPane(m_jtrProviders, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                                         JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        m_jspProviders.setPreferredSize(new Dimension(350, 200));
        m_jpProviders.add(m_jspProviders, BorderLayout.CENTER);

        getContentPane().add(m_jpProviders, BorderLayout.CENTER);
        getContentPane().add(m_jpButtons, BorderLayout.SOUTH);

        setTitle(m_res.getString("DProviderInfo.Title"));
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
     * Create tree node with information on all loaded providers.
     *
     * @return The tree node
     */
    private DefaultMutableTreeNode createProviderNodes()
    {
        // Top node
        DefaultMutableTreeNode topNode = new DefaultMutableTreeNode(m_res.getString("DProviderInfo.TopNodeName"));

        // Get security providers
        Provider[] providers = Security.getProviders();

        // For each provider...
        for (int iCnt=0; iCnt < providers.length; iCnt++)
        {
            Provider provider = providers[iCnt];

            // Create a node with the provider name and add it as a child of the top node
            DefaultMutableTreeNode providerNode = new DefaultMutableTreeNode(provider.getName());
            topNode.add(providerNode);

            // Add child nodes to the provider node for provider decription and version
            providerNode.add(new DefaultMutableTreeNode(provider.getInfo()));
            providerNode.add(new DefaultMutableTreeNode(""+provider.getVersion()));

            // Create another child node called properties and...
            DefaultMutableTreeNode providerPropertiesNode = new DefaultMutableTreeNode(m_res.getString("DProviderInfo.ProviderProperties"));
            providerNode.add(providerPropertiesNode);

            // ...add property child nodes to it
            for (Enumeration enum = provider.propertyNames(); enum.hasMoreElements();)
            {
                String sKey = (String)enum.nextElement();
                String sValue = provider.getProperty(sKey);

                providerPropertiesNode.add(new DefaultMutableTreeNode(MessageFormat.format(m_res.getString("DProviderInfo.ProviderProperty"), new String[]{sKey, sValue})));
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
        StringBuffer strBuff = new StringBuffer();

        // Get security providers
        Provider[] providers = Security.getProviders();

        // For each provider...
        for (int iCnt=0; iCnt < providers.length; iCnt++)
        {
            Provider provider = providers[iCnt];

            // ...write out the provider name, description and version...
            strBuff.append(MessageFormat.format(m_res.getString("DProviderInfo.Copy.ProviderName"), new Object[]{provider.getName()}));
            strBuff.append('\n');
            strBuff.append(MessageFormat.format(m_res.getString("DProviderInfo.Copy.ProviderVersion"), new Object[]{""+provider.getVersion()}));
            strBuff.append('\n');
            strBuff.append(MessageFormat.format(m_res.getString("DProviderInfo.Copy.ProviderDescription"), new Object[]{provider.getInfo()}));
            strBuff.append('\n');
            strBuff.append(m_res.getString("DProviderInfo.Copy.ProviderProperties"));
            strBuff.append('\n');

            // ...and it's properties
            for (Enumeration en = provider.propertyNames(); en.hasMoreElements();)
            {
                String sKey = (String) en.nextElement();
                String sValue = provider.getProperty(sKey);

                strBuff.append('\t');
                strBuff.append(sKey);
                strBuff.append('=');
                strBuff.append(sValue);
                strBuff.append('\n');
            }

            if ((iCnt+1) < providers.length)
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
