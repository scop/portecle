/*
 * DImportKeyPair.java
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
import java.text.MessageFormat;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;

import net.sf.portecle.crypto.*;
import net.sf.portecle.gui.error.DThrowable;

/**
 * Dialog that displays the details of all key pairs from a PKCS #12
 * KeyStore allowing the user to pick one for import.
 */
class DImportKeyPair extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Panel to hold key pair information */
    private JPanel m_jpKeyPairs;

    /** Instructions text */
    private JLabel m_jlInstructions;

    /** List of key pairs availabel for import */
    private JList m_jltKeyPairs;

    /** Scroll pane to contain key pair list */
    private JScrollPane m_jspKeyPairs;

    /** Panel to hold details specfic to to the selected key pair */
    private JPanel m_jpKeyPairDetails;

    /** Selected key pair's algorithm label */
    private JLabel m_jlAlgorithm;

    /** Selected key pair's algorithm text field */
    private JTextField m_jtfAlgorithm;

    /** Button to press to display the selected key pair's certificate
     * details */
    private JButton m_jbCertificateDetails;

    /** Panel for confirmation button controls */
    private JPanel m_jpButtons;

    /** Import button to import a key pair */
    private JButton m_jbImport;

    /** Cancel button to cancel dialog */
    private JButton m_jbCancel;

    /** Key from input map to action map for the cancel button */
    private static final String CANCEL_KEY = "CANCEL_KEY";

    /** PKCS #12 KeyStore */
    private KeyStore m_pkcs12;

    /** Private key part of key pair chosen by the user for import */
    private Key m_privateKey;

    /** Certificate chain part of key pair chosen by the user for import */
    private Certificate[] m_certificateChain;

    /**
     * Creates new form DImportKeyPair where the parent is a frame.
     *
     * @param parent The parent frame
     * @param bModal Is dialog modal?
     * @param pkcs12 The PKCS #12 KeyStore to list key pairs from
     * @throws CryptoException A problem was encountered importing a key pair.
     */
    public DImportKeyPair(JFrame parent, boolean bModal, KeyStore pkcs12)
        throws CryptoException
    {
        super(parent, bModal);
        m_pkcs12 = pkcs12;
        initComponents();
    }

    /**
     * Initialise the dialog's GUI components.
     *
     * @throws CryptoException A problem was encountered importing a key pair
     */
    private void initComponents() throws CryptoException
    {
        // Instructions
        m_jlInstructions = new JLabel(
            m_res.getString("DImportKeyPair.m_jlInstructions.text"));

        // List to hold KeyStore's key pair aliases
        m_jltKeyPairs = new JList();
        m_jltKeyPairs.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        m_jltKeyPairs.addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent evt) {
                populateAlgorithm();
                if (m_jltKeyPairs.getSelectedIndex() == -1)
                {
                    m_jbImport.setEnabled(false);
                    m_jbCertificateDetails.setEnabled(false);
                }
                else
                {
                    m_jbImport.setEnabled(true);
                    m_jbCertificateDetails.setEnabled(true);
                }
            }
        });

        // Put the list into a scroll pane
        m_jspKeyPairs = new JScrollPane(
            m_jltKeyPairs,
            JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
            JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        m_jspKeyPairs.getViewport().setBackground(
            m_jltKeyPairs.getBackground());

        // Key Pair details (algorithm and button to access
        // certificate details)
        m_jlAlgorithm = new JLabel(
            m_res.getString("DImportKeyPair.m_jlAlgorithm.text"));

        m_jtfAlgorithm = new JTextField(10);
        m_jtfAlgorithm.setText("");
        m_jtfAlgorithm.setToolTipText(
            m_res.getString("DImportKeyPair.m_jtfAlgorithm.tooltip"));
        m_jtfAlgorithm.setEditable(false);

        m_jbCertificateDetails = new JButton(
            m_res.getString("DImportKeyPair.m_jbCertificateDetails.text"));
        m_jbCertificateDetails.setMnemonic(
            m_res.getString("DImportKeyPair.m_jbCertificateDetails.mnemonic")
            .charAt(0));
        m_jbCertificateDetails.setToolTipText(
            m_res.getString("DImportKeyPair.m_jbCertificateDetails.tooltip"));
        m_jbCertificateDetails.setEnabled(false);
        m_jbCertificateDetails.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                certificateDetailsPressed();
            }
        });

        m_jpKeyPairDetails = new JPanel(new FlowLayout(FlowLayout.LEFT));
        m_jpKeyPairDetails.add(m_jlAlgorithm);
        m_jpKeyPairDetails.add(m_jtfAlgorithm);
        m_jpKeyPairDetails.add(m_jbCertificateDetails);

        // Put all the key pair components together
        m_jpKeyPairs = new JPanel(new BorderLayout(10, 10));
        m_jpKeyPairs.setPreferredSize(new Dimension(400, 200));
        m_jpKeyPairs.setBorder(
            new CompoundBorder(
                new CompoundBorder(new EmptyBorder(5, 5, 5, 5),
                                   new EtchedBorder()),
                new EmptyBorder(5, 5, 5, 5)));

        m_jpKeyPairs.add(m_jlInstructions, BorderLayout.NORTH);
        m_jpKeyPairs.add(m_jspKeyPairs, BorderLayout.CENTER);
        m_jpKeyPairs.add(m_jpKeyPairDetails, BorderLayout.SOUTH);

        // Create import and cancel buttons
        m_jbImport = new JButton(
            m_res.getString("DImportKeyPair.m_jbImport.text"));
        m_jbImport.setEnabled(false);
        m_jbImport.setMnemonic(
            m_res.getString("DImportKeyPair.m_jbImport.mnemonic").charAt(0));
        m_jbImport.setToolTipText(
            m_res.getString("DImportKeyPair.m_jbImport.tooltip"));
        m_jbImport.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                importPressed();
            }
        });

        m_jbCancel = new JButton(
            m_res.getString("DImportKeyPair.m_jbCancel.text"));
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
        m_jpButtons.add(m_jbImport);
        m_jpButtons.add(m_jbCancel);

        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(m_jpKeyPairs, BorderLayout.CENTER);
        getContentPane().add(m_jpButtons, BorderLayout.SOUTH);

        // Populate the list
        populateList();

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        setTitle(m_res.getString("DImportKeyPair.Title"));
        setResizable(false);

        getRootPane().setDefaultButton(m_jbImport);

        pack();

        if (m_jbImport.isEnabled())
        {
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    m_jbImport.requestFocus();
                }
            });
        }
        else
        {
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    m_jbCancel.requestFocus();
                }
            });
        }
    }

    /**
     * Populate the key pair list with the PKCS #12 KeyStore's key
     * pair aliases.
     *
     * @throws CryptoException Problem accessing the KeyStore's entries
     */
    private void populateList() throws CryptoException
    {
        try
        {
            Vector vKeyPairAliases = new Vector();

            // For each entry in the KeyStore...
            for (Enumeration aliases = m_pkcs12.aliases();
                 aliases.hasMoreElements();)
            {
                // Get alias...
                String sAlias = (String)aliases.nextElement();

                // Add the alias to the list if the entry has a key
                // and certificates
                if (m_pkcs12.isKeyEntry(sAlias))
                {
                    Key key = m_pkcs12.getKey(sAlias, new char[]{});
                    Certificate[] certs = m_pkcs12.getCertificateChain(sAlias);

                    if (certs != null && certs.length != 0)
                    {
                        vKeyPairAliases.add(sAlias);
                    }
                }
            }

            if (vKeyPairAliases.size() > 0)
            {
                m_jltKeyPairs.setListData(vKeyPairAliases);
                m_jltKeyPairs.setSelectedIndex(0);
            }
            else
            {
                // No key pairs available...
                m_jltKeyPairs.setListData(
                    new String[]{
                        m_res.getString(
                            "DImportKeyPair.m_jltKeyPairs.empty")});
                m_jltKeyPairs.setEnabled(false);
            }
        }
        catch (GeneralSecurityException ex)
        {
            throw new CryptoException(
                m_res.getString(
                    "DImportKeyPair.ProblemAccessingPkcs12.exception.message"),
                ex);
        }
    }

    /**
     * Populate the algorithm text field.  If a key pair is selected
     * then the field will contain the key pairs algorithm name and
     * key size.  Otherwise the field will be blanked.
     */
    private void populateAlgorithm()
    {
        try
        {
            String sAlias = (String)m_jltKeyPairs.getSelectedValue();

            if (sAlias == null)
            {
                m_jtfAlgorithm.setText("");
                return;
            }

            // Get the algorithm information from the appropriate
            // certificate - we can't yet use an API to get it
            // directly from the private key
            Certificate[] certs = m_pkcs12.getCertificateChain(sAlias);

            X509Certificate[] x509Certs =
                X509CertUtil.convertCertificates(certs);

            if (x509Certs == null)
            {
                m_jtfAlgorithm.setText("");
                return;
            }

            x509Certs = X509CertUtil.orderX509CertChain(x509Certs);

            X509Certificate keyPairCert = x509Certs[0];

            int iKeySize = X509CertUtil.getCertificateKeyLength(keyPairCert);
            m_jtfAlgorithm.setText(keyPairCert.getPublicKey().getAlgorithm());

            if (iKeySize != -1)
            {
                m_jtfAlgorithm.setText(
                    MessageFormat.format(
                        m_res.getString("DImportKeyPair.m_jtfAlgorithm.text"),
                        new String[]{m_jtfAlgorithm.getText(), ""+iKeySize}));
            }
            m_jtfAlgorithm.setCaretPosition(0);
        }
        catch (KeyStoreException ex)
        {
            displayException(ex);
            closeDialog();
        }
        catch (CryptoException ex)
        {
            displayException(ex);
            closeDialog();
        }
    }

    /**
     * Certificate Details button pressed.  Display the selected key
     * pair's certificates.
     */
    private void certificateDetailsPressed()
    {
        try
        {
            String sAlias = (String)m_jltKeyPairs.getSelectedValue();

            assert sAlias != null;

            X509Certificate[] certs = X509CertUtil.convertCertificates(
                m_pkcs12.getCertificateChain(sAlias));

            DViewCertificate dViewCertificate = new DViewCertificate(
                this,
                MessageFormat.format(
                    m_res.getString(
                        "DImportKeyPair.ViewCertificateDetails.Title"),
                    new String[]{sAlias}),
                true,
                certs);
            dViewCertificate.setLocationRelativeTo(this);
            dViewCertificate.setVisible(true);
        }
        catch (KeyStoreException ex)
        {
            displayException(ex);
            closeDialog();
        }
        catch (CryptoException ex)
        {
            displayException(ex);
            closeDialog();
        }
    }

    /**
     * Get the private part of the key pair chosen by the user for import.
     *
     * @return The private key or null if the user has not chosen a key pair
     */
    public Key getPrivateKey()
    {
        return m_privateKey;
    }

    /**
     * Get the certificate chain part of the key pair chosen by the
     * user for import.
     *
     * @return The certificate chain or null if the user has not
     * chosen a key pair
     */
    public Certificate[] getCertificateChain()
    {
        return m_certificateChain;
    }

    /**
     * Import button pressed by user.  Store the selected key pair's
     * private and public parts and close the dialog.
     */
    public void importPressed()
    {
        String sAlias = (String)m_jltKeyPairs.getSelectedValue();

        assert sAlias != null;

        try
        {
            m_privateKey = m_pkcs12.getKey(sAlias, new char[]{});
            m_certificateChain = m_pkcs12.getCertificateChain(sAlias);
        }
        catch (KeyStoreException ex)
        {
            displayException(ex);
            closeDialog();
        }
        catch (NoSuchAlgorithmException ex)
        {
            displayException(ex);
            closeDialog();
        }
        catch (UnrecoverableKeyException ex)
        {
            displayException(ex);
            closeDialog();
        }

        closeDialog();
    }

    /**
     * Display an exception.
     *
     * @param exception Exception to display
     */
    private void displayException(Exception exception)
    {
        DThrowable dThrowable = new DThrowable(this, true, exception);
        dThrowable.setLocationRelativeTo(this);
        dThrowable.setVisible(true);
    }

    /**
     * Cancel button pressed - close the dialog.
     */
    public void cancelPressed()
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
