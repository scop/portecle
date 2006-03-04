/*
 * DExport.java
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

package net.sf.portecle;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.border.TitledBorder;

import net.sf.portecle.crypto.CryptoException;

/**
 * Dialog used to export keystore entries.  A number of export types
 * and formats are available depending on the entries content.
 */
class DExport extends JDialog
{
    /** Key from input map to action map for the cancel button */
    private static final String CANCEL_KEY = "CANCEL_KEY";

    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Panel containing all of the export type option controls */
    private JPanel m_jpExportType;

    /** Head certificate only export type radio button */
    private JRadioButton m_jrbHeadCertOnly;

    /** Certificate chain export type radio button */
    private JRadioButton m_jrbCertChain;

    /** Private key and certificate chain export type radio button */
    private JRadioButton m_mjrbPrivKeyCertChain;

    /** Panel containing all of the export format option controls */
    private JPanel m_jpExportFormat;

    /** DER Encoded export format radio button */
    private JRadioButton m_jrbDEREncoded;

    /** PEM Encoded export format radio button */
    private JRadioButton m_jrbPemEncoded;

    /** PKCS #7 export format radio button */
    private JRadioButton m_jrbPKCS7;

    /** PkiPath export format radio button */
    private JRadioButton m_jrbPkiPath;

    /** PKCS #12 export format radio button */
    private JRadioButton m_jrbPKCS12;

    /** Panel containing all of the export option controls */
    private JPanel m_jpOptions;

    /** The keystore to to export from */
    private KeyStoreWrapper m_keyStoreWrap;

    /** The keystore entry to export */
    private String m_sEntryAlias;

    /** Panel for confirmation button controls */
    private JPanel m_jpButtons;

    /** OK button to confirm dialog */
    private JButton m_jbOK;

    /** Cancel button to cancel dialog */
    private JButton m_jbCancel;

    /** Records whether or not the an export is selected */
    private boolean m_bExportSelected;

    /**
     * Creates new form DExport where the parent is a frame.
     *
     * @param parent The parent frame
     * @param bModal Is dialog modal?
     * @param keyStore The keystore to export from
     * @param sEntryAlias The keystore entry to export
     * @throws CryptoException Problem accessing the keystore entry
     */
    public DExport(JFrame parent, boolean bModal, KeyStoreWrapper keyStore,
                   String sEntryAlias)
        throws CryptoException
    {
        super(parent, bModal);
        m_keyStoreWrap = keyStore;
        m_sEntryAlias = sEntryAlias;
        initComponents();
    }

    /**
     * Initialise the dialog's GUI components.
     *
     * @throws CryptoException Problem accessing the keystore entry
     */
    private void initComponents() throws CryptoException
    {
        // Export type controls
        m_jpExportType = new JPanel(new GridLayout(3, 1));
        m_jpExportType.setBorder(
            new TitledBorder(m_res.getString("DExport.m_jpExportType.text")));

        m_jrbHeadCertOnly = new JRadioButton(
            m_res.getString("DExport.m_jrbHeadCertOnly.text"), true);
        m_jrbHeadCertOnly.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent evt) {
                m_jrbDEREncoded.setEnabled(true);
                if (m_jrbPKCS12.isSelected())
                {
                    m_jrbDEREncoded.setSelected(true);
                }
                m_jrbPemEncoded.setEnabled(true);
                m_jrbPKCS7.setEnabled(true);
                m_jrbPkiPath.setEnabled(true);
                m_jrbPKCS12.setEnabled(false);
            }
        });

        m_jrbCertChain = new JRadioButton(
            m_res.getString("DExport.m_jrbCertChain.text"));
        m_jrbCertChain.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent evt) {
                m_jrbDEREncoded.setEnabled(false);
                m_jrbPemEncoded.setEnabled(false);
                m_jrbPKCS7.setEnabled(true);
                if (!m_jrbPkiPath.isSelected())
                {
                    m_jrbPKCS7.setSelected(true);
                }
                m_jrbPkiPath.setEnabled(true);
                m_jrbPKCS12.setEnabled(false);
            }
        });

        m_mjrbPrivKeyCertChain = new JRadioButton(
            m_res.getString("DExport.m_jrbPrivKeyCertChain.text"));
        m_mjrbPrivKeyCertChain.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent evt) {
                m_jrbDEREncoded.setEnabled(false);
                m_jrbPemEncoded.setEnabled(false);
                m_jrbPKCS7.setEnabled(false);
                m_jrbPkiPath.setEnabled(false);
                m_jrbPKCS12.setEnabled(true);
                m_jrbPKCS12.setSelected(true);
            }
        });

        ButtonGroup typeBG = new ButtonGroup();
        typeBG.add(m_jrbHeadCertOnly);
        typeBG.add(m_jrbCertChain);
        typeBG.add(m_mjrbPrivKeyCertChain);

        m_jpExportType.add(m_jrbHeadCertOnly);
        m_jpExportType.add(m_jrbCertChain);
        m_jpExportType.add(m_mjrbPrivKeyCertChain);

        // Export format controls
        // @@@TODO: add item listeners for these
        m_jpExportFormat = new JPanel(new GridLayout(5, 1));
        m_jpExportFormat.setBorder(
            new TitledBorder(
                m_res.getString("DExport.m_jpExportFormat.text")));

        m_jrbDEREncoded = new JRadioButton(
            m_res.getString("DExport.m_jrbDEREncoded.text"), true);
        m_jrbPemEncoded = new JRadioButton(
            m_res.getString("DExport.m_jrbPemEncoded.text"));
        m_jrbPKCS7 = new JRadioButton(
            m_res.getString("DExport.m_jrbPKCS7.text"));
        m_jrbPkiPath = new JRadioButton(
            m_res.getString("DExport.m_jrbPkiPath.text"));
        m_jrbPKCS12 = new JRadioButton(
            m_res.getString("DExport.m_jrbPKCS12.text"));
        m_jrbPKCS12.setEnabled(false);

        ButtonGroup formatBG = new ButtonGroup();
        formatBG.add(m_jrbDEREncoded);
        formatBG.add(m_jrbPemEncoded);
        formatBG.add(m_jrbPKCS7);
        formatBG.add(m_jrbPkiPath);
        formatBG.add(m_jrbPKCS12);

        m_jpExportFormat.add(m_jrbDEREncoded);
        m_jpExportFormat.add(m_jrbPemEncoded);
        m_jpExportFormat.add(m_jrbPKCS7);
        m_jpExportFormat.add(m_jrbPkiPath);
        m_jpExportFormat.add(m_jrbPKCS12);

        // Disable radio boxes depending on entry type
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        try
        {
            if (keyStore.isCertificateEntry(m_sEntryAlias))
            {
                m_jrbCertChain.setEnabled(false);
                m_mjrbPrivKeyCertChain.setEnabled(false);
            }
        }
        catch (KeyStoreException ex)
        {
            String sMessage = MessageFormat.format(
                m_res.getString("DExport.NoAccessEntry.message"),
                new String[]{m_sEntryAlias});
            throw new CryptoException(sMessage, ex);
        }

        // Put all export option controls together in one panel
        m_jpOptions = new JPanel(new BorderLayout(10, 0));
        m_jpOptions.setBorder(
            new CompoundBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5),
                                                  new EtchedBorder()),
                               new EmptyBorder(5, 5, 5, 5)));

        m_jpOptions.add(m_jpExportType, BorderLayout.NORTH);
        m_jpOptions.add(m_jpExportFormat, BorderLayout.SOUTH);

        // Buttons
        m_jbOK = new JButton(m_res.getString("DExport.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        m_jbCancel = new JButton(m_res.getString("DExport.m_jbCancel.text"));
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

        // Put it all together
        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(m_jpOptions, BorderLayout.CENTER);
        getContentPane().add(m_jpButtons, BorderLayout.SOUTH);

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        setTitle(MessageFormat.format(
                     m_res.getString("DExport.Title"),
                     new String[]{m_sEntryAlias}));
        setResizable(false);

        getRootPane().setDefaultButton(m_jbOK);

        pack();
    }

    /**
     * Has an export been selected?
     *
     * @return True if it has, false otherwise
     */
    public boolean exportSelected()
    {
        return m_bExportSelected;
    }

    /**
     * Has the user chosen to export only head certificate?
     *
     * @return True if they have, false otherwise
     */
    public boolean exportHead()
    {
        return m_jrbHeadCertOnly.isSelected();
    }

    /**
     * Has the user chosen to export the entire chain of certificates?
     *
     * @return True if they have, false otherwise
     */
    public boolean exportChain()
    {
        return m_jrbCertChain.isSelected();
    }

    /**
     * Has the user chosen to export the entire chain of certificates
     * and the private key?
     *
     * @return True if they have, false otherwise
     */
    public boolean exportKeyChain()
    {
        return m_mjrbPrivKeyCertChain.isSelected();
    }

    /**
     * Has the user chosen to export as DER?
     *
     * @return True if they have, false otherwise
     */
    public boolean exportDer()
    {
        return m_jrbDEREncoded.isSelected();
    }

    /**
     * Has the user chosen to export as PEM?
     *
     * @return True if they have, false otherwise
     */
    public boolean exportPem()
    {
        return m_jrbPemEncoded.isSelected();
    }

    /**
     * Has the user chosen to export as PKCS #7?
     *
     * @return True if they have, false otherwise
     */
    public boolean exportPkcs7()
    {
        return m_jrbPKCS7.isSelected();
    }

    /**
     * Has the user chosen to export as PkiPath?
     *
     * @return True if they have, false otherwise
     */
    public boolean exportPkiPath()
    {
        return m_jrbPkiPath.isSelected();
    }

    /**
     * Has the user chosen to export as PKCS #12?
     *
     * @return True if they have, false otherwise
     */
    public boolean exportPkcs12()
    {
        return m_jrbPKCS12.isSelected();
    }

    /**
     * OK button pressed or otherwise activated.
     */
    private void okPressed()
    {
        m_bExportSelected = true;

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
