/*
 * DNewKeyStoreType.java
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

package net.sf.portecle;

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;

import net.sf.portecle.crypto.KeyStoreType;

/**
 * Dialog used to retrieve the type to use in the creation of a new KeyStore.
 */
class DNewKeyStoreType extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Panel containing KeyStore type controls */
    private JPanel m_jpKeyStoreType;

    /** KeyStore type label */
    private JLabel m_jlKeyStoreType;

    /** JKS KeyStore type radio button */
    private JRadioButton m_jrbJksKeyStore;

    /** JCEKS KeyStore type radio button */
    private JRadioButton m_jrbJceksKeyStore;

    /** PKCS #12 KeyStore type radio button */
    private JRadioButton m_jrbPkcs12KeyStore;

    /** BKS KeyStore type radio button */
    private JRadioButton m_jrbBksKeyStore;

    /** UBER KeyStore type radio button */
    private JRadioButton m_jrbUberKeyStore;

    /** Panel for confirmation button controls */
    private JPanel m_jpButtons;

    /** OK button to confirm dialog */
    private JButton m_jbOK;

    /** Cancel button to cancel dialog */
    private JButton m_jbCancel;

    /** Key from input map to action map for the cancel button */
    private static final String CANCEL_KEY = "CANCEL_KEY";

    /** Stores the selected KeyStore type */
    KeyStoreType m_keyStoreType;

    /**
     * Creates new form DNewKeyStoreType where the parent is a frame.
     *
     * @param parent The parent frame
     * @param bModal Is dialog modal?
     */
    public DNewKeyStoreType(JFrame parent, boolean bModal)
    {
        super(parent, bModal);
        setTitle(m_res.getString("DNewKeyStoreType.Title"));
        initComponents();
    }

    /**
     * Initialise the dialog's GUI components.
     */
    private void initComponents()
    {
        // Create KeyStore type label and radio buttons and group them
        // in a panel
        m_jlKeyStoreType = new JLabel(
            m_res.getString("DNewKeyStoreType.m_jlKeyStoreType.text"));

        m_jrbJksKeyStore = new JRadioButton(
            m_res.getString("DNewKeyStoreType.m_jrbJksKeyStore.text"), true);
        m_jrbJksKeyStore.setMnemonic(
            m_res.getString("DNewKeyStoreType.m_jrbJksKeyStore.mnemonic")
            .charAt(0));
        m_jrbJksKeyStore.setToolTipText(
            m_res.getString("DNewKeyStoreType.m_jrbJksKeyStore.tooltip"));

        m_jrbJceksKeyStore = new JRadioButton(
            m_res.getString("DNewKeyStoreType.m_jrbJceksKeyStore.text"));
        m_jrbJceksKeyStore.setMnemonic(
            m_res.getString("DNewKeyStoreType.m_jrbJceksKeyStore.mnemonic")
            .charAt(0));
        m_jrbJceksKeyStore.setToolTipText(
            m_res.getString("DNewKeyStoreType.m_jrbJceksKeyStore.tooltip"));

        m_jrbPkcs12KeyStore = new JRadioButton(
            m_res.getString("DNewKeyStoreType.m_jrbPkcs12KeyStore.text"));
        m_jrbPkcs12KeyStore.setMnemonic(
            m_res.getString("DNewKeyStoreType.m_jrbPkcs12KeyStore.mnemonic")
            .charAt(0));
        m_jrbPkcs12KeyStore.setToolTipText(
            m_res.getString("DNewKeyStoreType.m_jrbPkcs12KeyStore.tooltip"));

        m_jrbBksKeyStore = new JRadioButton(
            m_res.getString("DNewKeyStoreType.m_jrbBksKeyStore.text"));
        m_jrbBksKeyStore.setMnemonic(
            m_res.getString("DNewKeyStoreType.m_jrbBksKeyStore.mnemonic")
            .charAt(0));
        m_jrbBksKeyStore.setToolTipText(
            m_res.getString("DNewKeyStoreType.m_jrbBksKeyStore.tooltip"));

        m_jrbUberKeyStore = new JRadioButton(
            m_res.getString("DNewKeyStoreType.m_jrbUberKeyStore.text"));
        m_jrbUberKeyStore.setMnemonic(
            m_res.getString("DNewKeyStoreType.m_jrbUberKeyStore.mnemonic")
            .charAt(0));
        m_jrbUberKeyStore.setToolTipText(
            m_res.getString("DNewKeyStoreType.m_jrbUberKeyStore.tooltip"));

        ButtonGroup keyStoreTypes = new ButtonGroup();

        keyStoreTypes.add(m_jrbJksKeyStore);
        keyStoreTypes.add(m_jrbJceksKeyStore);
        keyStoreTypes.add(m_jrbPkcs12KeyStore);
        keyStoreTypes.add(m_jrbBksKeyStore);
        keyStoreTypes.add(m_jrbUberKeyStore);

        m_jpKeyStoreType = new JPanel(new GridLayout(6, 1));
        m_jpKeyStoreType.setBorder(
            new CompoundBorder(
                new EmptyBorder(5, 5, 5, 5),
                new CompoundBorder(new EtchedBorder(),
                                   new EmptyBorder(5, 5, 5, 5))));

        m_jpKeyStoreType.add(m_jlKeyStoreType);
        m_jpKeyStoreType.add(m_jrbJksKeyStore);
        m_jpKeyStoreType.add(m_jrbJceksKeyStore);
        m_jpKeyStoreType.add(m_jrbPkcs12KeyStore);
        m_jpKeyStoreType.add(m_jrbBksKeyStore);
        m_jpKeyStoreType.add(m_jrbUberKeyStore);

        // Create confirmation buttons and place them in a panel
        m_jbOK = new JButton(m_res.getString("DNewKeyStoreType.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        m_jbCancel = new JButton(
            m_res.getString("DNewKeyStoreType.m_jbCancel.text"));
        m_jbCancel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });
        m_jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);
        m_jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction () {
                public void actionPerformed(ActionEvent evt) {
                    cancelPressed();
                }});

        m_jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
        m_jpButtons.add(m_jbOK);
        m_jpButtons.add(m_jbCancel);

        // Place both panels on the dialog
        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(m_jpKeyStoreType, BorderLayout.CENTER);
        getContentPane().add(m_jpButtons, BorderLayout.SOUTH);

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        setResizable(false);

        getRootPane().setDefaultButton(m_jbOK);

        pack();
    }

    /**
     * Get the selected KeyStore type.
     *
     * @return The selected KeyStore type or null if none was selected
     */
    public KeyStoreType getKeyStoreType()
    {
        return m_keyStoreType;
    }

    /**
     * OK button pressed or otherwise activated.
     */
    private void okPressed()
    {
        // Store selected KeyStore type
        if (m_jrbJksKeyStore.isSelected())
        {
            m_keyStoreType = KeyStoreType.JKS;
        }
        else if (m_jrbJceksKeyStore.isSelected())
        {
            m_keyStoreType = KeyStoreType.JCEKS;
        }
        else if (m_jrbPkcs12KeyStore.isSelected())
        {
            m_keyStoreType = KeyStoreType.PKCS12;
        }
        else if (m_jrbBksKeyStore.isSelected())
        {
            m_keyStoreType = KeyStoreType.BKS;
        }
        else
        {
            m_keyStoreType = KeyStoreType.UBER;
        }

        closeDialog();
    }

    /**
     * Cancel button pressed or otherwise activated.
     */
    private void cancelPressed()
    {
        closeDialog();
    }

    /**
     * Closes the dialog.
     */
    private void closeDialog()
    {
        setVisible(false);
        dispose();
    }
}
