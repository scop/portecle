/*
 * DViewCRL.java
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
import java.text.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.math.BigInteger;
import java.security.cert.*;

import net.sf.portecle.crypto.CryptoException;
import net.sf.portecle.gui.error.DThrowable;

/**
 * Displays the details of a Certificate Revocation List (CRL).
 */
class DViewCRL extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Panel to hold OK button */
    private JPanel m_jpOK;

    /** OK button to dismiss dialog */
    private JButton m_jbOK;

    /** Panel to hold CRL detail */
    private JPanel m_jpCRL;

    /** CRL Verison label */
    private JLabel m_jlVersion;

    /** CRL Verison text field */
    private JTextField m_jtfVersion;

    /** CRL Issuer label */
    private JLabel m_jlIssuer;

    /** CRL Issuer text field */
    private JTextField m_jtfIssuer;

    /** CRL EffectiveDate label */
    private JLabel m_jlEffectiveDate;

    /** CRL EffectiveDate text field */
    private JTextField m_jtfEffectiveDate;

    /** CRL Next Update label */
    private JLabel m_jlNextUpdate;

    /** CRL Next Update text field */
    private JTextField m_jtfNextUpdate;

    /** CRL Signature Algorithm label */
    private JLabel m_jlSignatureAlgorithm;

    /** CRL Signature Algorithm text field */
    private JTextField m_jtfSignatureAlgorithm;

    /** Button used to display the CRL's extensions */
    private JButton m_jbCrlExtensions;

    /** Panel to hold Revoked Certficates table */
    private JPanel m_jpRevokedCertsTable;

    /** Scroll Pane to view Revoked Certificates table */
    private JScrollPane m_jspRevokedCertsTable;

    /** Revoked Certificates table */
    private JTable m_jtRevokedCerts;

    /** Panel to hold CRL's entries' extensions button */
    private JPanel m_jpCrlEntryExtensions;

    /** Button used to display the CRL's entries' extensions */
    private JButton m_jbCrlEntryExtensions;

    /** Stores CRL to display */
    private X509CRL m_crl;

    /**
     * Creates new DViewCRL dialog where the parent is a frame.
     *
     * @param parent Parent frame
     * @param sTitle The dialog title
     * @param bModal Is dialog modal?
     * @param crl CRL to display
     */
    public DViewCRL(JFrame parent, String sTitle, boolean bModal, X509CRL crl)
    {
        super(parent, sTitle, bModal);
        m_crl = crl;
        initComponents();
    }

    /**
     * Creates new DViewCRL dialog where the parent is a dialog.
     *
     * @param parent Parent dialog
     * @param sTitle The dialog title
     * @param bModal Is dialog modal?
     * @param crl CRL to display
     */
    public DViewCRL(JDialog parent, String sTitle, boolean bModal, X509CRL crl)
    {
        super(parent, sTitle, bModal);
        m_crl = crl;
        initComponents();
    }

    /**
     * Initialise the dialog's GUI components.
     */
    private void initComponents()
    {
        // CRL Details:

        // Grid Bag Constraints templates for labels and text fields
        // of CRL details
        GridBagConstraints gbcLbl = new GridBagConstraints();
        gbcLbl.gridx = 0;
        gbcLbl.gridwidth = 1;
        gbcLbl.gridheight = 1;
        gbcLbl.insets = new Insets(5, 5, 5, 5);
        gbcLbl.anchor = GridBagConstraints.EAST;

        GridBagConstraints gbcTf = new GridBagConstraints();
        gbcTf.gridx = 1;
        gbcTf.gridwidth = 1;
        gbcTf.gridheight = 1;
        gbcTf.insets = new Insets(5, 5, 5, 5);
        gbcTf.anchor = GridBagConstraints.WEST;

        // Version
        m_jlVersion = new JLabel(m_res.getString("DViewCRL.m_jlVersion.text"));
        GridBagConstraints gbc_jlVersion = (GridBagConstraints)gbcLbl.clone();
        gbc_jlVersion.gridy = 0;

        m_jtfVersion = new JTextField(3);
        m_jtfVersion.setEditable(false);
        m_jtfVersion.setToolTipText(
            m_res.getString("DViewCRL.m_jtfVersion.tooltip"));
        GridBagConstraints gbc_jtfVersion = (GridBagConstraints)gbcTf.clone();
        gbc_jtfVersion.gridy = 0;

        // Issuer
        m_jlIssuer = new JLabel(m_res.getString("DViewCRL.m_jlIssuer.text"));
        GridBagConstraints gbc_jlIssuer = (GridBagConstraints)gbcLbl.clone();
        gbc_jlIssuer.gridy = 1;

        m_jtfIssuer = new JTextField(40);
        m_jtfIssuer.setEditable(false);
        m_jtfIssuer.setToolTipText(
            m_res.getString("DViewCRL.m_jtfIssuer.tooltip"));
        GridBagConstraints gbc_jtfIssuer = (GridBagConstraints)gbcTf.clone();
        gbc_jtfIssuer.gridy = 1;

        // Effective Date
        m_jlEffectiveDate = new JLabel(
            m_res.getString("DViewCRL.m_jlEffectiveDate.text"));
        GridBagConstraints gbc_jlEffectiveDate =
            (GridBagConstraints) gbcLbl.clone();
        gbc_jlEffectiveDate.gridy = 2;

        m_jtfEffectiveDate = new JTextField(30);
        m_jtfEffectiveDate.setEditable(false);
        m_jtfEffectiveDate.setToolTipText(
            m_res.getString("DViewCRL.m_jtfEffectiveDate.tooltip"));
        GridBagConstraints gbc_jtfEffectiveDate =
            (GridBagConstraints) gbcTf.clone();
        gbc_jtfEffectiveDate.gridy = 2;

        // Next Update
        m_jlNextUpdate = new JLabel(
            m_res.getString("DViewCRL.m_jlNextUpdate.text"));
        GridBagConstraints gbc_jlNextUpdate =
            (GridBagConstraints) gbcLbl.clone();
        gbc_jlNextUpdate.gridy = 3;

        m_jtfNextUpdate = new JTextField(30);
        m_jtfNextUpdate.setEditable(false);
        m_jtfNextUpdate.setToolTipText(
            m_res.getString("DViewCRL.m_jtfNextUpdate.tooltip"));
        GridBagConstraints gbc_jtfNextUpdate =
            (GridBagConstraints) gbcTf.clone();
        gbc_jtfNextUpdate.gridy = 3;

        // Signature Algorithm
        m_jlSignatureAlgorithm = new JLabel(
            m_res.getString("DViewCRL.m_jlSignatureAlgorithm.text"));
        GridBagConstraints gbc_jlSignatureAlgorithm =
            (GridBagConstraints) gbcLbl.clone();
        gbc_jlSignatureAlgorithm.gridy = 4;

        m_jtfSignatureAlgorithm = new JTextField(15);
        m_jtfSignatureAlgorithm.setEditable(false);
        m_jtfSignatureAlgorithm.setToolTipText(
            m_res.getString("DViewCRL.m_jtfSignatureAlgorithm.tooltip"));
        GridBagConstraints gbc_jtfSignatureAlgorithm =
            (GridBagConstraints) gbcTf.clone();
        gbc_jtfSignatureAlgorithm.gridy = 4;

        // CRL Extensions
        m_jbCrlExtensions = new JButton(
            m_res.getString("DViewCRL.m_jbCrlExtensions.text"));

        m_jbCrlExtensions.setMnemonic(
            m_res.getString("DViewCRL.m_jbCrlExtensions.mnemonic").charAt(0));
        m_jbCrlExtensions.setToolTipText(
            m_res.getString("DViewCRL.m_jbCrlExtensions.tooltip"));
        m_jbCrlExtensions.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                crlExtensionsPressed();
            }
        });

        GridBagConstraints gbc_jbExtensions = new GridBagConstraints();
        gbc_jbExtensions.gridx = 0;
        gbc_jbExtensions.gridy = 5;
        gbc_jbExtensions.gridwidth = 2;
        gbc_jbExtensions.gridheight = 1;
        gbc_jbExtensions.insets = new Insets(5, 5, 5, 5);
        gbc_jbExtensions.anchor = GridBagConstraints.EAST;

        // Revoked certificates table

        // Create the table using the appropriate table model
        RevokedCertsTableModel rcModel = new RevokedCertsTableModel();

        m_jtRevokedCerts = new JTable(rcModel);

        m_jtRevokedCerts.setShowGrid(false);
        m_jtRevokedCerts.setRowMargin(0);
        m_jtRevokedCerts.getColumnModel().setColumnMargin(0);
        m_jtRevokedCerts.getTableHeader().setReorderingAllowed(false);
        m_jtRevokedCerts.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);

        // Add custom renderers for the table cells and headers
        for (int iCnt=0; iCnt < m_jtRevokedCerts.getColumnCount(); iCnt++)
        {
            TableColumn column =
                m_jtRevokedCerts.getColumnModel().getColumn(iCnt);

            if (iCnt == 0)
            {
                column.setPreferredWidth(150);
            }

            column.setHeaderRenderer(new RevokedCertsTableHeadRend());
            column.setCellRenderer(new RevokedCertsTableCellRend());
        }

        ListSelectionModel listSelectionModel =
            m_jtRevokedCerts.getSelectionModel();
        listSelectionModel.addListSelectionListener(
            new ListSelectionListener() {
                public void valueChanged(ListSelectionEvent evt)
                    {
                        // Ignore spurious events
                        if (!evt.getValueIsAdjusting())
                        {
                            crlEntrySelection();
                        }
                    }
            });

        // Put the table into a scroll pane
        m_jspRevokedCertsTable = new JScrollPane(
            m_jtRevokedCerts,
            JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
            JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        m_jspRevokedCertsTable.getViewport().setBackground(
            m_jtRevokedCerts.getBackground());

        // Put the scroll pane into a panel
        m_jpRevokedCertsTable = new JPanel(new BorderLayout(10, 10));
        // More for the benefit of a reduced height
        m_jpRevokedCertsTable.setPreferredSize(new Dimension(100, 200));
        m_jpRevokedCertsTable.add(m_jspRevokedCertsTable, BorderLayout.CENTER);
        m_jpRevokedCertsTable.setBorder(
            new CompoundBorder(
                new TitledBorder(new EtchedBorder(),
                                 m_res.getString("DViewCRL.TableTitle")),
                new EmptyBorder(5, 5, 5, 5)));

        // CRL Entry Extensions
        m_jbCrlEntryExtensions = new JButton(
            m_res.getString("DViewCRL.m_jbCrlEntryExtensions.text"));

        m_jbCrlEntryExtensions.setMnemonic(
            m_res.getString(
                "DViewCRL.m_jbCrlEntryExtensions.mnemonic").charAt(0));
        m_jbCrlEntryExtensions.setToolTipText(
            m_res.getString("DViewCRL.m_jbCrlEntryExtensions.tooltip"));
        m_jbCrlEntryExtensions.setEnabled(false);
        m_jbCrlEntryExtensions.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                crlEntryExtensionsPressed();
            }
        });

        m_jpCrlEntryExtensions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        m_jpCrlEntryExtensions.add(m_jbCrlEntryExtensions);

        m_jpRevokedCertsTable.add(m_jpCrlEntryExtensions, BorderLayout.SOUTH);

        GridBagConstraints gbc_jpRevokedCertsTable = new GridBagConstraints();
        gbc_jpRevokedCertsTable.gridx = 0;
        gbc_jpRevokedCertsTable.gridy = 6;
        gbc_jpRevokedCertsTable.gridwidth = 2;
        gbc_jpRevokedCertsTable.gridheight = 1;
        gbc_jpRevokedCertsTable.insets = new Insets(5, 5, 5, 5);
        gbc_jpRevokedCertsTable.fill = GridBagConstraints.BOTH;
        gbc_jpRevokedCertsTable.anchor = GridBagConstraints.CENTER;

        m_jpCRL = new JPanel(new GridBagLayout());
        m_jpCRL.setBorder(new CompoundBorder(new EmptyBorder(10, 10, 10, 10),
                                             new EtchedBorder()));

        // Put it all together
        m_jpCRL.add(m_jlVersion, gbc_jlVersion);
        m_jpCRL.add(m_jtfVersion, gbc_jtfVersion);
        m_jpCRL.add(m_jlIssuer, gbc_jlIssuer);
        m_jpCRL.add(m_jtfIssuer, gbc_jtfIssuer);
        m_jpCRL.add(m_jlEffectiveDate, gbc_jlEffectiveDate);
        m_jpCRL.add(m_jtfEffectiveDate, gbc_jtfEffectiveDate);
        m_jpCRL.add(m_jlNextUpdate, gbc_jlNextUpdate);
        m_jpCRL.add(m_jtfNextUpdate, gbc_jtfNextUpdate);
        m_jpCRL.add(m_jlSignatureAlgorithm, gbc_jlSignatureAlgorithm);
        m_jpCRL.add(m_jtfSignatureAlgorithm, gbc_jtfSignatureAlgorithm);
        m_jpCRL.add(m_jbCrlExtensions, gbc_jbExtensions);
        m_jpCRL.add(m_jpRevokedCertsTable, gbc_jpRevokedCertsTable);

        // Populate the dialog with the CRL
        populateDialog();

        // OK button
        m_jpOK = new JPanel(new FlowLayout(FlowLayout.CENTER));

        m_jbOK = new JButton(m_res.getString("DViewCRL.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        m_jpOK.add(m_jbOK);

        // Put it all together
        getContentPane().add(m_jpCRL, BorderLayout.CENTER);
        getContentPane().add(m_jpOK, BorderLayout.SOUTH);

        setResizable(false);

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
     * Populate the dialog with the CRL's details.
     */
    private void populateDialog()
    {
        // Populate CRL fields:

        // Has the CRL [been issued/been updated]
        Date currentDate = new Date();

        Date effectiveDate = m_crl.getThisUpdate();
        Date updateDate = m_crl.getNextUpdate();

        boolean bEffective = currentDate.before(effectiveDate);
        boolean bUpdateAvailable = currentDate.after(updateDate);

        // Version
        m_jtfVersion.setText(Integer.toString(m_crl.getVersion()));
        m_jtfVersion.setCaretPosition(0);

        // Issuer
        m_jtfIssuer.setText(m_crl.getIssuerDN().toString());
        m_jtfIssuer.setCaretPosition(0);

        // Effective Date (include timezone)
        m_jtfEffectiveDate.setText(
            DateFormat.getDateTimeInstance(
                DateFormat.MEDIUM, DateFormat.LONG).format(effectiveDate));

        if (bEffective)
        {
            m_jtfEffectiveDate.setText(
                MessageFormat.format(
                    m_res.getString(
                        "DViewCRL.m_jtfEffectiveDate.noteffective.text"),
                    new String[]{m_jtfEffectiveDate.getText()}));
            m_jtfEffectiveDate.setForeground(Color.red);
        }
        else
        {
            m_jtfEffectiveDate.setForeground(m_jtfVersion.getForeground());
        }
        m_jtfEffectiveDate.setCaretPosition(0);

        // Next Update (include timezone)
        m_jtfNextUpdate.setText(
            DateFormat.getDateTimeInstance(
                DateFormat.MEDIUM, DateFormat.LONG).format(updateDate));

        if (bUpdateAvailable)
        {
            m_jtfNextUpdate.setText(
                MessageFormat.format(
                    m_res.getString(
                        "DViewCRL.m_jtfNextUpdate.updateavailable.text"),
                    new String[]{m_jtfNextUpdate.getText()}));
            m_jtfNextUpdate.setForeground(Color.red);
        }
        else
        {
            m_jtfNextUpdate.setForeground(m_jtfVersion.getForeground());
        }
        m_jtfNextUpdate.setCaretPosition(0);

        // Signature Algorithm
        m_jtfSignatureAlgorithm.setText(m_crl.getSigAlgName());
        m_jtfSignatureAlgorithm.setCaretPosition(0);

        // Enable/disable extensions button
        Set critExts = m_crl.getCriticalExtensionOIDs();
        Set nonCritExts = m_crl.getNonCriticalExtensionOIDs();

        if (((critExts != null) && (critExts.size() != 0)) ||
            ((nonCritExts != null) && (nonCritExts.size() != 0)))
        {
            // Extensions
            m_jbCrlExtensions.setEnabled(true);
        }
        else
        {
            // No extensions
            m_jbCrlExtensions.setEnabled(false);
        }

        // Populate Revoked Certificates table
        Set revokedCertsSet = m_crl.getRevokedCertificates();
        if (revokedCertsSet == null)
        {
            revokedCertsSet = new HashSet();
        }
        X509CRLEntry[] revokedCerts =
            (X509CRLEntry[]) revokedCertsSet.toArray(
                new X509CRLEntry[revokedCertsSet.size()]);
        RevokedCertsTableModel revokedCertsTableModel =
            (RevokedCertsTableModel) m_jtRevokedCerts.getModel();
        revokedCertsTableModel.load(revokedCerts);

        // Select first CRL
        if (revokedCertsTableModel.getRowCount() > 0)
        {
            m_jtRevokedCerts.changeSelection(0, 0, false, false);
        }
    }

    /**
     * CRL entry selected or deselected.  Enable/disable the "CRL
     * Extensions" button accordingly (ie. enable if if only one
     * extension is selected and it has extensions.
     */
    private void crlEntrySelection()
    {
        ListSelectionModel listSelectionModel =
            m_jtRevokedCerts.getSelectionModel();

        if (!listSelectionModel.isSelectionEmpty()) // Enry must be selected
        {
            // Only one entry though
            if (listSelectionModel.getMinSelectionIndex() ==
                listSelectionModel.getMaxSelectionIndex())
            {
                // Get serial number of entry
                int iRow = listSelectionModel.getMinSelectionIndex();
                BigInteger serialNumber = (BigInteger)
                    ((RevokedCertsTableModel)m_jtRevokedCerts.getModel())
                    .getValueAt(iRow, 0);

                // Find CRL entry using serial number
                Set revokedCertsSet = m_crl.getRevokedCertificates();

                X509CRLEntry x509CrlEntry = null;

                for (Iterator itr = revokedCertsSet.iterator(); itr.hasNext();)
                {
                    X509CRLEntry entry = (X509CRLEntry) itr.next();
                    if (serialNumber.equals(entry.getSerialNumber()))
                    {
                        x509CrlEntry = entry;
                        break;
                    }
                }

                if (x509CrlEntry.hasExtensions()) // Entry has extensions
                {
                    // Enable "CRL Extensions" button and return
                    m_jbCrlEntryExtensions.setEnabled(true);
                    return;
                }
            }
        }

        // Disable "CRL Extensions" button
        m_jbCrlEntryExtensions.setEnabled(false);
    }

    /**
     * CRL extensions button pressed or otherwise activated.  Show the
     * extensions of the CRL.
     */
    private void crlExtensionsPressed()
    {
        try
        {
            DViewExtensions dViewExtensions = new DViewExtensions(
                this, m_res.getString("DViewCRL.Extensions.Title"), true,
                m_crl);
            dViewExtensions.setLocationRelativeTo(this);
            dViewExtensions.setVisible(true);
        }
        catch (CryptoException ex)
        {
            DThrowable dThrowable = new DThrowable(this, true, ex);
            dThrowable.setLocationRelativeTo(this);
            dThrowable.setVisible(true);
            return;
        }
    }

    /**
     * CRL entry extensions button pressed or otherwise activated.  Show the
     * extensions of the selected CRL entry.
     */
    private void crlEntryExtensionsPressed()
    {
        ListSelectionModel listSelectionModel =
            m_jtRevokedCerts.getSelectionModel();

        if (!listSelectionModel.isSelectionEmpty()) // Entry must be selected
        {
            // Only one entry though
            if (listSelectionModel.getMinSelectionIndex() ==
                listSelectionModel.getMaxSelectionIndex())
            {
                // Get serial number of entry
                int iRow = listSelectionModel.getMinSelectionIndex();
                BigInteger serialNumber = (BigInteger)
                    ((RevokedCertsTableModel) m_jtRevokedCerts.getModel())
                    .getValueAt(iRow, 0);

                // Find CRL entry using serial number
                Set revokedCertsSet = m_crl.getRevokedCertificates();

                X509CRLEntry x509CrlEntry = null;

                for (Iterator itr = revokedCertsSet.iterator(); itr.hasNext();)
                {
                    X509CRLEntry entry = (X509CRLEntry) itr.next();
                    if (serialNumber.equals(entry.getSerialNumber()))
                    {
                        x509CrlEntry = entry;
                        break;
                    }
                }

                if (x509CrlEntry.hasExtensions()) // Entry has extensions
                {
                    try
                    {
                        // View extensions
                        DViewExtensions dViewExtensions =
                            new DViewExtensions(this,
                                                m_res.getString(
                                                    "DViewCRL." +
                                                    "EntryExtensions.Title"),
                                                true, x509CrlEntry);
                        dViewExtensions.setLocationRelativeTo(this);
                        dViewExtensions.setVisible(true);
                    }
                    catch (CryptoException ex)
                    {
                        DThrowable dThrowable = new DThrowable(this, true, ex);
                        dThrowable.setLocationRelativeTo(this);
                        dThrowable.setVisible(true);
                        return;
                    }
                }
            }
        }
    }

    /**
     * OK button pressed or otherwise activated.
     */
    private void okPressed()
    {
        closeDialog();
    }

    /**
     * Hides the View CRL dialog.
     */
    private void closeDialog()
    {
        setVisible(false);
        dispose();
    }
}
