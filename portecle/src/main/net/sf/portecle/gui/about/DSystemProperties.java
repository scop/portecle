/*
 * DSystemProperties.java
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

package net.sf.portecle.gui.about;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableColumn;

/**
 * A dialog that displays the Java System Properties.
 */
public class DSystemProperties extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/gui/about/resources");

    /** OK button used to dismiss dialog */
    private JButton m_jbOK;

    /** Panel containing buttons */
    private JPanel m_jpOK;

    /** Panel to hold System Properties table */
    private JPanel m_jpSystemPropertiesTable;

    /** Scroll Pane to view System Properties table */
    private JScrollPane m_jspSystemPropertiesTable;

    /** System Properties table */
    private JTable m_jtSystemProperties;

    /**
     * Creates new DSystemProperties dialog where the parent is a dialog.
     *
     * @param parent Parent dialog
     * @param bModal Is dialog modal?     
     */
    public DSystemProperties(JDialog parent, boolean bModal)
    {
        this(parent, m_res.getString("DSystemProperties.Title"), bModal);
    }

    /**
     * Creates new DSystemProperties dialog where the parent is a dialog.
     *
     * @param parent Parent dialog
     * @param sTitle The title of the dialog
     * @param bModal Is dialog modal?     
     */
    public DSystemProperties(JDialog parent, String sTitle, boolean bModal)
    {
        super(parent, sTitle, bModal);
        initComponents();
    }

    /**
     * Initialise the dialog's GUI components.     
     */
    private void initComponents()
    {       
        // System Properties table

        // Create the table using the appropriate table model
        SystemPropertiesTableModel spModel = new SystemPropertiesTableModel();
        spModel.load();

        m_jtSystemProperties = new JTable(spModel);

        m_jtSystemProperties.setRowMargin(0);
        m_jtSystemProperties.getColumnModel().setColumnMargin(0);
        m_jtSystemProperties.getTableHeader().setReorderingAllowed(false);
        m_jtSystemProperties.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        // Add custom renderers for the table cells and headers
        int tWidth = 30; // arbitrary # of pixels for vertical scrollbar
        for (int iCnt=0; iCnt < m_jtSystemProperties.getColumnCount(); iCnt++)
        {
            TableColumn column =
                m_jtSystemProperties.getColumnModel().getColumn(iCnt);

            if (iCnt == 0)
            {
                int w = 210;
                column.setPreferredWidth(w); // Property Name
                tWidth += w;
            }
            else
            {
                int w = 320;
                column.setPreferredWidth(w); // Property Value
                tWidth += w;
            }

            column.setHeaderRenderer(new SystemPropertiesTableHeadRend());
            column.setCellRenderer(new SystemPropertiesTableCellRend());
        }

        // Put the table into a scroll panew
        m_jspSystemPropertiesTable = new JScrollPane(
            m_jtSystemProperties,
            JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
            JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        m_jspSystemPropertiesTable.getViewport().setBackground(
            m_jtSystemProperties.getBackground());

        // Put the scroll pane into a panel
        m_jpSystemPropertiesTable = new JPanel(new BorderLayout(10, 10));
        m_jpSystemPropertiesTable.setPreferredSize(new Dimension(tWidth, 300));
        m_jpSystemPropertiesTable.add(
            m_jspSystemPropertiesTable, BorderLayout.CENTER);
        m_jpSystemPropertiesTable.setBorder(new EmptyBorder(5, 5, 5, 5));

        m_jbOK = new JButton(m_res.getString("DSystemProperties.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        m_jpOK = new JPanel(new FlowLayout(FlowLayout.CENTER));        
        m_jpOK.add(m_jbOK);

        getContentPane().add(m_jpSystemPropertiesTable, BorderLayout.CENTER);
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
     * OK button pressed or otherwise activated.
     */
    private void okPressed()
    {
        closeDialog();
    }

    /**
     * Close the dialog.
     */
    private void closeDialog()
    {
        setVisible(false);
        dispose();
    }
}
