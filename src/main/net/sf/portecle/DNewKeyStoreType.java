/*
 * DNewKeyStoreType.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2005-2006 Ville Skyttä, ville.skytta@iki.fi
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
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import net.sf.portecle.crypto.KeyStoreType;
import net.sf.portecle.crypto.KeyStoreUtil;

/**
 * Dialog used to retrieve the type to use in the creation of a new keystore.
 */
class DNewKeyStoreType
    extends JDialog
{
    /** Key from input map to action map for the cancel button */
    private static final String CANCEL_KEY = "CANCEL_KEY";

    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Stores the selected keystore type */
    private KeyStoreType m_keyStoreType;

    /** JKS keystore type radio button */
    private JRadioButton m_jrbJksKeyStore;

    /** JCEKS keystore type radio button */
    private JRadioButton m_jrbJceksKeyStore;

    /** PKCS #12 keystore type radio button */
    private JRadioButton m_jrbPkcs12KeyStore;

    /** BKS keystore type radio button */
    private JRadioButton m_jrbBksKeyStore;

    /** UBER keystore type radio button */
    private JRadioButton m_jrbUberKeyStore;

    /** GKR keystore type radio button */
    private JRadioButton m_jrbGkrKeyStore;

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
        // Create keystore type label and radio buttons and group them
        // in a panel
        JLabel jlKeyStoreType = new JLabel(
            m_res.getString("DNewKeyStoreType.jlKeyStoreType.text"));

        m_jrbJksKeyStore = new JRadioButton(
            m_res.getString("DNewKeyStoreType.m_jrbJksKeyStore.text"), true);
        m_jrbJksKeyStore.setMnemonic(m_res.getString(
            "DNewKeyStoreType.m_jrbJksKeyStore.mnemonic").charAt(0));
        m_jrbJksKeyStore.setToolTipText(m_res.getString("DNewKeyStoreType.m_jrbJksKeyStore.tooltip"));
        m_jrbJksKeyStore.setEnabled(KeyStoreUtil.isAvailable(KeyStoreType.JKS));

        m_jrbJceksKeyStore = new JRadioButton(
            m_res.getString("DNewKeyStoreType.m_jrbJceksKeyStore.text"));
        m_jrbJceksKeyStore.setMnemonic(m_res.getString(
            "DNewKeyStoreType.m_jrbJceksKeyStore.mnemonic").charAt(0));
        m_jrbJceksKeyStore.setToolTipText(m_res.getString("DNewKeyStoreType.m_jrbJceksKeyStore.tooltip"));
        m_jrbJceksKeyStore.setEnabled(KeyStoreUtil.isAvailable(KeyStoreType.JCEKS));

        m_jrbPkcs12KeyStore = new JRadioButton(
            m_res.getString("DNewKeyStoreType.m_jrbPkcs12KeyStore.text"));
        m_jrbPkcs12KeyStore.setMnemonic(m_res.getString(
            "DNewKeyStoreType.m_jrbPkcs12KeyStore.mnemonic").charAt(0));
        m_jrbPkcs12KeyStore.setToolTipText(m_res.getString("DNewKeyStoreType.m_jrbPkcs12KeyStore.tooltip"));

        m_jrbBksKeyStore = new JRadioButton(
            m_res.getString("DNewKeyStoreType.m_jrbBksKeyStore.text"));
        m_jrbBksKeyStore.setMnemonic(m_res.getString(
            "DNewKeyStoreType.m_jrbBksKeyStore.mnemonic").charAt(0));
        m_jrbBksKeyStore.setToolTipText(m_res.getString("DNewKeyStoreType.m_jrbBksKeyStore.tooltip"));

        m_jrbUberKeyStore = new JRadioButton(
            m_res.getString("DNewKeyStoreType.m_jrbUberKeyStore.text"));
        m_jrbUberKeyStore.setMnemonic(m_res.getString(
            "DNewKeyStoreType.m_jrbUberKeyStore.mnemonic").charAt(0));
        m_jrbUberKeyStore.setToolTipText(m_res.getString("DNewKeyStoreType.m_jrbUberKeyStore.tooltip"));

        m_jrbGkrKeyStore = new JRadioButton(
            m_res.getString("DNewKeyStoreType.m_jrbGkrKeyStore.text"));
        m_jrbGkrKeyStore.setMnemonic(m_res.getString(
            "DNewKeyStoreType.m_jrbGkrKeyStore.mnemonic").charAt(0));
        m_jrbGkrKeyStore.setToolTipText(m_res.getString("DNewKeyStoreType.m_jrbGkrKeyStore.tooltip"));
        m_jrbGkrKeyStore.setEnabled(KeyStoreUtil.isAvailable(KeyStoreType.GKR));

        ButtonGroup keyStoreTypes = new ButtonGroup();

        keyStoreTypes.add(m_jrbJksKeyStore);
        keyStoreTypes.add(m_jrbPkcs12KeyStore);
        keyStoreTypes.add(m_jrbJceksKeyStore);
        keyStoreTypes.add(m_jrbBksKeyStore);
        keyStoreTypes.add(m_jrbUberKeyStore);
        keyStoreTypes.add(m_jrbGkrKeyStore);

        if (m_jrbJksKeyStore.isEnabled()) {
            m_jrbJksKeyStore.setSelected(true);
        }
        else {
            m_jrbPkcs12KeyStore.setSelected(true);
        }

        JPanel jpKeyStoreType = new JPanel(
            new GridLayout(keyStoreTypes.getButtonCount() + 1, 1));
        jpKeyStoreType.setBorder(new CompoundBorder(
            new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
                new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

        jpKeyStoreType.add(jlKeyStoreType);
        jpKeyStoreType.add(m_jrbJksKeyStore);
        jpKeyStoreType.add(m_jrbPkcs12KeyStore);
        jpKeyStoreType.add(m_jrbJceksKeyStore);
        jpKeyStoreType.add(m_jrbBksKeyStore);
        jpKeyStoreType.add(m_jrbUberKeyStore);
        jpKeyStoreType.add(m_jrbGkrKeyStore);

        // Create confirmation buttons and place them in a panel
        JButton jbOK = new JButton(
            m_res.getString("DNewKeyStoreType.jbOK.text"));
        jbOK.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                okPressed();
            }
        });

        JButton jbCancel = new JButton(
            m_res.getString("DNewKeyStoreType.jbCancel.text"));
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

        JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
        jpButtons.add(jbOK);
        jpButtons.add(jbCancel);

        // Place both panels on the dialog
        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(jpKeyStoreType, BorderLayout.CENTER);
        getContentPane().add(jpButtons, BorderLayout.SOUTH);

        addWindowListener(new WindowAdapter()
        {
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
     * Get the selected keystore type.
     *
     * @return The selected keystore type or null if none was selected
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
        // Store selected keystore type
        if (m_jrbJksKeyStore.isSelected()) {
            m_keyStoreType = KeyStoreType.JKS;
        }
        else if (m_jrbJceksKeyStore.isSelected()) {
            m_keyStoreType = KeyStoreType.JCEKS;
        }
        else if (m_jrbPkcs12KeyStore.isSelected()) {
            m_keyStoreType = KeyStoreType.PKCS12;
        }
        else if (m_jrbBksKeyStore.isSelected()) {
            m_keyStoreType = KeyStoreType.BKS;
        }
        else if (m_jrbUberKeyStore.isSelected()) {
            m_keyStoreType = KeyStoreType.UBER;
        }
        else if (m_jrbGkrKeyStore.isSelected()) {
            m_keyStoreType = KeyStoreType.GKR;
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
