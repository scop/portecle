/*
 * DViewExtensions.java
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

package net.sf.portecle;

import java.util.*;
import java.text.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.security.cert.*;

import net.sf.portecle.crypto.*;
import net.sf.portecle.gui.error.DThrowable;

/**
 * Displays the details of X.509 Extensions.
 */
class DViewExtensions extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Panel to hold extensions controls */
    private JPanel m_jpExtensions;

    /** Panel to hold Extensions table */
    private JPanel m_jpExtensionsTable;

    /** Scroll Pane to view Extensions table */
    private JScrollPane m_jspExtensionsTable;

    /** Extensions table */
    private JTable m_jtExtensions;

    /** Panel to hold Extension Value controls */
    private JPanel m_jpExtensionValue;

    /** Label for Extension Value */
    private JLabel m_jlExtensionValue;

    /** Panel to hold Extension Value text area */
    private JPanel m_jpExtensionValueTextArea;

    /** Scroll Pane to view Extension Value text area */
    private JScrollPane m_jspExtensionValue;

    /** Extension value text area */
    private JTextArea m_jtaExtensionValue;

    /** Panel to hold OK button */
    private JPanel m_jpOK;

    /** OK button to dismiss dialog */
    private JButton m_jbOK;

    /** Extensions to display */
    private X509Extension m_extensions;

    /**
     * Creates new DViewExtensions dialog where the parent is a frame.
     *
     * @param parent Parent frame
     * @param sTitle The dialog title
     * @param bModal Is dialog modal?
     * @param extensions Extensions to display
     * @throws CryptoException A problem was encountered getting the extension details
     */
    public DViewExtensions(JFrame parent, String sTitle, boolean bModal, X509Extension extensions)
        throws CryptoException
    {
        super(parent, sTitle, bModal);
        m_extensions = extensions;
        initComponents();
    }

    /**
     * Creates new DViewExtensions dialog where the parent is a dialog.
     *
     * @param parent Parent dialog
     * @param sTitle The dialog title
     * @param bModal Is dialog modal?
     * @param extensions Extensions to display
     * @throws CryptoException A problem was encountered getting the extension details
     */
    public DViewExtensions(JDialog parent, String sTitle, boolean bModal, X509Extension extensions)
        throws CryptoException
    {
        super(parent, sTitle, bModal);
        m_extensions = extensions;
        initComponents();
    }

    /**
     * Initialise the dialog's GUI components.
     */
    private void initComponents()
    {
        // There must be extensions to display
        assert (((m_extensions.getCriticalExtensionOIDs() != null) &&
                 (m_extensions.getCriticalExtensionOIDs().size() != 0)) ||
                ((m_extensions.getNonCriticalExtensionOIDs() != null) &&
                 (m_extensions.getNonCriticalExtensionOIDs().size() != 0)));

        // Extensions table

        // Create the table using the appropriate table model
        ExtensionsTableModel extensionsTableModel = new ExtensionsTableModel();
        m_jtExtensions = new JTable(extensionsTableModel);

        m_jtExtensions.setShowGrid(false);
        m_jtExtensions.setRowMargin(0);
        m_jtExtensions.getColumnModel().setColumnMargin(0);
        m_jtExtensions.getTableHeader().setReorderingAllowed(false);
        m_jtExtensions.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        m_jtExtensions.setRowHeight(18);

        // Add custom renderers for the table cells and headers
        for (int iCnt=0; iCnt < m_jtExtensions.getColumnCount(); iCnt++)
        {
            TableColumn column =  m_jtExtensions.getColumnModel().getColumn(iCnt);
            column.setHeaderRenderer(new ExtensionsTableHeadRend());
            column.setCellRenderer(new ExtensionsTableCellRend());
        }

        /* Make the first column small and not resizable (it holds an icon to
           represent the criticality of an extension) */
        TableColumn criticalCol = m_jtExtensions.getColumnModel().getColumn(0);
        criticalCol.setResizable(false);
        criticalCol.setMinWidth(20);
        criticalCol.setMaxWidth(20);
        criticalCol.setPreferredWidth(20);

        // If extension selected/deselected update extension value text area
        ListSelectionModel selectionModel = m_jtExtensions.getSelectionModel();
        selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        selectionModel.addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent evt) {
                if (!evt.getValueIsAdjusting())
                {
                    updateExtensionValue();
                }
            }
        });

        // Put the table into a scroll pane
        m_jspExtensionsTable = new JScrollPane(m_jtExtensions,
                                               JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                                               JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        m_jspExtensionsTable.getViewport().setBackground(m_jtExtensions.getBackground());

        // Put the scroll pane into a panel
        m_jpExtensionsTable = new JPanel(new BorderLayout(10, 10));
        m_jpExtensionsTable.setPreferredSize(new Dimension(350, 200));
        m_jpExtensionsTable.add(m_jspExtensionsTable, BorderLayout.CENTER);

        // Panel to hold Extension Value controls
        m_jpExtensionValue = new JPanel(new BorderLayout(10, 10));

        // Extension Value label
        m_jlExtensionValue = new JLabel(m_res.getString("DViewExtensions.m_jlExtensionValue.text"));

        // Put label into panel
        m_jpExtensionValue.add(m_jlExtensionValue, BorderLayout.NORTH);

        // Extension Value text area
        m_jtaExtensionValue = new JTextArea();
        m_jtaExtensionValue.setFont(new Font("Monospaced", Font.PLAIN, m_jtaExtensionValue.getFont().getSize()));
        m_jtaExtensionValue.setEditable(false);
        m_jtaExtensionValue.setToolTipText(m_res.getString("DViewExtensions.m_jtaExtensionValue.tooltip"));

        // Put the text area into a scroll pane
        m_jspExtensionValue = new JScrollPane(m_jtaExtensionValue,
                                              JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                                              JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        // Put the scroll pane into a panel
        m_jpExtensionValueTextArea = new JPanel(new BorderLayout(10, 10));
        m_jpExtensionValueTextArea.setPreferredSize(new Dimension(350, 200));
        m_jpExtensionValueTextArea.add(m_jspExtensionValue, BorderLayout.CENTER);

        // Put text area panel into Extension Value controls panel
        m_jpExtensionValue.add(m_jpExtensionValueTextArea, BorderLayout.CENTER);

        // Put Extensions table and Extension Value text area together in extensions panel
        m_jpExtensions = new JPanel(new GridLayout(1, 2, 5, 5));
        m_jpExtensions.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5),
                                                    new CompoundBorder(new EtchedBorder(),
                                                                       new EmptyBorder(5, 5, 5, 5))));

        m_jpExtensions.add(m_jpExtensionsTable);
        m_jpExtensions.add(m_jpExtensionValue);

        // OK button
        m_jpOK = new JPanel(new FlowLayout(FlowLayout.CENTER));

        m_jbOK = new JButton(m_res.getString("DViewExtensions.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        m_jpOK.add(m_jbOK);

        // Populate table with extensions
        extensionsTableModel.load(m_extensions);

        // Select first extension
        if (extensionsTableModel.getRowCount() > 0)
        {
            m_jtExtensions.changeSelection(0, 0, false, false);
        }

        // Put it all together
        getContentPane().add(m_jpExtensions, BorderLayout.CENTER);
        getContentPane().add(m_jpOK, BorderLayout.SOUTH);

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
     * Update the value of the Extension Value text area depending on whether
     * or not an extension has been selected in the table.
     */
    private void updateExtensionValue()
    {
        int iSelectedRow = m_jtExtensions.getSelectedRow();

        if (iSelectedRow == -1)
        {
            // No extension selected - clear text area
            m_jtaExtensionValue.setText("");
        }
        else
        {
            // Extension selected - get value for extension
            String sOid = m_jtExtensions.getModel().getValueAt(iSelectedRow, 2).toString();

            byte[] bValue = m_extensions.getExtensionValue(sOid);

            X509Ext ext = new X509Ext(sOid, bValue, false); // Don't care about criticality

            try
            {
                m_jtaExtensionValue.setText(ext.getStringValue());
            }
            catch (Exception ex) // Don't like catching exception but *anything* could go wrong in there
            {
                m_jtaExtensionValue.setText("");
                DThrowable dThrowable = new DThrowable(this, true, ex);
                dThrowable.setLocationRelativeTo(this);
                dThrowable.setVisible(true);
            }
            m_jtaExtensionValue.setCaretPosition(0);
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
     * Hides the View Extensions dialog.
     */
    private void closeDialog()
    {
        setVisible(false);
        dispose();
    }
}
