/*
 * DJarInfo.java
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

package net.sf.portecle.gui.jar;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.table.*;
import java.io.*;
import java.util.*;
import java.util.jar.*;

/**
 * A dialog that displays information about the JAR files on the classpath.
 */
public class DJarInfo extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/gui/jar/resources");

    /** OK button used to dismiss dialog */
    private JButton m_jbOK;

    /** Panel containing buttons */
    private JPanel m_jpOK;

    /** Panel to hold JAR Information table */
    private JPanel m_jpJarInfoTable;

    /** Scroll Pane to view JAR Information table */
    private JScrollPane m_jspJarInfoTable;

    /** JAR Information table */
    private JTable m_jtJarInfo;

    /**
     * Creates new DJarInfo dialog where the parent is a frame.
     *
     * @param parent Parent frame
     * @param bModal Is dialog modal?
     * @throws IOException Problem occurred getting JAR information
     */
    public DJarInfo(JFrame parent, boolean bModal) throws IOException
    {
        this(parent, m_res.getString("DJarInfo.Title"), bModal);
    }

    /**
     * Creates new DJarInfo dialog where the parent is a frame.
     *
     * @param parent Parent frame
     * @param sTitle The title of the dialog
     * @param bModal Is dialog modal?
     * @throws IOException Problem occurred getting JAR information
     */
    public DJarInfo(JFrame parent, String sTitle, boolean bModal) throws IOException
    {
        super(parent, sTitle, bModal);
        initComponents();
    }

    /**
     * Initialise the dialog's GUI components.
     *
     * @throws IOException Problem occurred getting JAR information
     */
    private void initComponents() throws IOException
    {
        JarFile[] jarFiles = getClassPathJars();

        // JAR Information table

        // Create the table using the appropriate table model
        JarInfoTableModel jiModel = new JarInfoTableModel();
        jiModel.load(jarFiles);

        m_jtJarInfo = new JTable(jiModel);

        m_jtJarInfo.setRowMargin(0);
        m_jtJarInfo.getColumnModel().setColumnMargin(0);
        m_jtJarInfo.getTableHeader().setReorderingAllowed(false);
        m_jtJarInfo.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        // Add custom renderers for the table cells and headers
        for (int iCnt=0; iCnt < m_jtJarInfo.getColumnCount(); iCnt++)
        {
            TableColumn column =  m_jtJarInfo.getColumnModel().getColumn(iCnt);

            column.setPreferredWidth(150);

            column.setHeaderRenderer(new JarInfoTableHeadRend());
            column.setCellRenderer(new JarInfoTableCellRend());
        }

        // Put the table into a scroll panew
        m_jspJarInfoTable = new JScrollPane(m_jtJarInfo,
                                            JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                                            JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        m_jspJarInfoTable.getViewport().setBackground(m_jtJarInfo.getBackground());

        // Put the scroll pane into a panel
        m_jpJarInfoTable = new JPanel(new BorderLayout(10, 10));
        m_jpJarInfoTable.setPreferredSize(new Dimension(500, 150));
        m_jpJarInfoTable.add(m_jspJarInfoTable, BorderLayout.CENTER);
        m_jpJarInfoTable.setBorder(new EmptyBorder(5, 5, 5, 5));

        m_jbOK = new JButton(m_res.getString("DJarInfo.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        m_jpOK = new JPanel(new FlowLayout(FlowLayout.CENTER));
        m_jpOK.add(m_jbOK);

        getContentPane().add(m_jpJarInfoTable, BorderLayout.CENTER);
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
     * Get JARs on classpath.
     *
     * @return JARs on classpath
     * @throws IOException Problem occurred getting JARs
     */
    private JarFile[] getClassPathJars() throws IOException
    {
        // Store JARs
        Vector vJars = new Vector();

        // Split classpath into it's components using the path separarator
        String sClassPath = System.getProperty("java.class.path");
        String sPathSeparator = System.getProperty("path.separator");

        StringTokenizer strTok = new StringTokenizer(sClassPath, sPathSeparator);

        // Store each JAR found on classpath
        while (strTok.hasMoreTokens())
        {
            String sClassPathEntry = strTok.nextToken();

            File file = new File(sClassPathEntry);

            if (isJarFile(file))
            {
                vJars.add(new JarFile(file));
            }
        }

        /* If only one JAR was found assume that application was started using "jar"
           option - look in JAR manifest's Class-Path entry for the rest of the JARs */
        if (vJars.size() == 1)
        {
            // Get manifest
            JarFile jarFile = (JarFile)vJars.get(0);
            Manifest manifest = jarFile.getManifest();

            if (manifest != null) // Manifest may not exist
            {
                // Get Class-Path entry
                Attributes attributes = manifest.getMainAttributes();
                String sJarClassPath = attributes.getValue("Class-Path");

                if (sJarClassPath != null)
                {
                    // Split "JAR classpath" using spaces
                    strTok = new StringTokenizer(sJarClassPath, " ");

                    // Store each JAR found on "JAR classpath"
                    while (strTok.hasMoreTokens())
                    {
                        String sJarClassPathEntry = strTok.nextToken();

                        File file = new File(new File(jarFile.getName()).getParent(), sJarClassPathEntry);

                        if (isJarFile(file))
                        {
                            vJars.add(new JarFile(file));
                        }
                    }
                }
            }
        }

        // Return JARs in an array
        return (JarFile[])vJars.toArray(new JarFile[vJars.size()]);
    }

    /**
     * Is supplied file a JAR file? That is, is it a regular file that it has an extension
     * of "ZIP" or "JAR".
     *
     * @param file The file
     * @return True if it is, false otherwise
     */
    private boolean isJarFile(File file)
    {
        if (file.isFile())
        {
            String sName = file.getName();

            if ((sName.endsWith(".jar")) || (sName.endsWith(".JAR")) ||
                (sName.endsWith(".zip")) || (sName.endsWith(".ZIP")))
            {
                return true;
            }
        }

        return false;
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
