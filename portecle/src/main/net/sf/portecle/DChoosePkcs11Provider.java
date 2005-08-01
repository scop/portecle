/*
 * DChoosePkcs11Provider.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Ville Skyttä, ville.skytta@iki.fi
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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.Provider;
import java.security.Security;
import java.text.MessageFormat;
import java.util.Iterator;
import java.util.ResourceBundle;
import java.util.TreeSet;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.KeyStroke;
import javax.swing.border.EmptyBorder;

import net.sf.portecle.crypto.ProviderUtil;

/**
 * Dialog used for choosing a PKCS #11 provider.
 *
 * @author Ville Skyttä
 */
public class DChoosePkcs11Provider
    extends JDialog
{
    /** Key from input map to action map for the cancel button */
    private static final String CANCEL_KEY = "CANCEL_KEY";

    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Panel to hold the provider choice controls */
    private JPanel m_jpProvider;

    /** Provider label */
    private JLabel m_jlProvider;

    /** Provider drop-down box */
    private JComboBox m_jcbProvider;

    /** Panel to hold confirmation buttons */
    private JPanel m_jpButtons;

    /** OK button to confirm dialog */
    private JButton m_jbOK;

    /** Cancel button to cancel dialog */
    private JButton m_jbCancel;

    /** Stores the provider chosen by the user */
    private String m_sProvider;


    /**
     * Creates new DChoosePkcs11Provider dialog where the parent is a frame.
     *
     * @param parent The parent frame
     * @param sTitle The dialog's title
     * @param bModal Is the dialog modal?
     * @param sOldProvider The provider to display initially
     */
    public DChoosePkcs11Provider(
        JFrame parent, String sTitle, boolean bModal, String sOldProvider)
    {
        super(parent, sTitle, bModal);
        initComponents(sOldProvider);
    }


    /**
     * Creates new DChoosePkcs11Provider dialog where the parent is a dialog.
     *
     * @param parent The parent dialog
     * @param sTitle The dialog's title
     * @param bModal Is the dialog modal?
     * @param sOldProvider The provider to display initially
     */
    public DChoosePkcs11Provider(
        JDialog parent, String sTitle, boolean bModal, String sOldProvider)
    {
        super(parent, sTitle, bModal);
        initComponents(sOldProvider);
    }


    /**
     * Get the provider chosen by the user.
     *
     * @return The provider, or null if none was entered
     */
    public String getProvider()
    {
        return m_sProvider;
    }


    /**
     * Initialise the dialog's GUI components.
     *
     * @param sOldProvider The provider to display initially
     */
    private void initComponents(String sOldProvider)
    {
        getContentPane().setLayout(new BorderLayout());

        m_jlProvider = new JLabel(
            m_res.getString("DChoosePkcs11Provider.m_jlProvider.text"));
        m_jcbProvider = new JComboBox();
        m_jcbProvider.setToolTipText(
            m_res.getString("DChoosePkcs11Provider.m_jcbProvider.tooltip"));

        TreeSet pSet = new TreeSet(ProviderUtil.getPkcs11Providers());

        boolean providersAvailable = !pSet.isEmpty();

        if (providersAvailable) {
            for (Iterator i = pSet.iterator(); i.hasNext();) {
                String pName = ((Provider) i.next()).getName();
                m_jcbProvider.addItem(pName);
                if (pName.equals(sOldProvider)) {
                    m_jcbProvider.setSelectedIndex(
                        m_jcbProvider.getItemCount() - 1);
                }
            }
        }
        else {
            m_jcbProvider.addItem(
                m_res.getString("DChoosePkcs11Provider.NoPkcs11Providers"));
            m_jcbProvider.setEnabled(false);
        }

        m_jbOK = new JButton(
            m_res.getString("DChoosePkcs11Provider.m_jbOK.text"));
        if (providersAvailable) {
            m_jbOK.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent evt) {
                        okPressed();
                    }
                });
        }
        else {
            m_jbOK.setEnabled(false);
        }

        m_jbCancel = new JButton(
            m_res.getString("DChoosePkcs11Provider.m_jbCancel.text"));
        m_jbCancel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });
        m_jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);
        m_jbCancel.getActionMap().put(
            CANCEL_KEY, new AbstractAction () {
                    public void actionPerformed(ActionEvent evt) {
                        cancelPressed();
                    }});

        m_jpProvider = new JPanel(new FlowLayout(FlowLayout.CENTER));
        m_jpProvider.add(m_jlProvider);
        m_jpProvider.add(m_jcbProvider);
        m_jpProvider.setBorder(new EmptyBorder(5, 5, 5, 5));

        m_jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
        m_jpButtons.add(m_jbOK);
        m_jpButtons.add(m_jbCancel);

        getContentPane().add(m_jpProvider, BorderLayout.CENTER);
        getContentPane().add(m_jpButtons, BorderLayout.SOUTH);

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        setResizable(false);

        getRootPane().setDefaultButton(
            providersAvailable ? m_jbOK : m_jbCancel);

        pack();
    }


    /**
     * Check that the chosen provider is valid.
     *
     * @return True if the provider is valid, false otherwise
     */
    private boolean checkProvider()
    {
        String sProvider = (String) m_jcbProvider.getSelectedItem();

        if (sProvider == null || Security.getProvider(sProvider) == null) {
            String msg = MessageFormat.format(
                m_res.getString(
                    "DChoosePkcs11Provider.InvalidProvider.message"),
                new String[]{sProvider});
            JOptionPane.showMessageDialog(
                this, msg, getTitle(), JOptionPane.WARNING_MESSAGE);
            return false;
        }

        m_sProvider = sProvider;
        return true;
    }


    /**
     * OK button pressed or otherwise activated.
     */
    private void okPressed()
    {
        if (checkProvider()) {
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
