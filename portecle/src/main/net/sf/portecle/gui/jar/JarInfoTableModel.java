/*
 * JarInfoTableModel.java
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

package net.sf.portecle.gui.jar;

import java.io.*;
import java.text.MessageFormat;
import java.util.*;
import java.util.jar.*;

import javax.swing.table.*;

/**
 * The table model used to display information about JAR files.
 */
class JarInfoTableModel extends AbstractTableModel
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/gui/jar/resources");

    /** Holds the column names */
    private String[] m_columnNames;

    /** Holds the table data */
    private Object[][] m_data;

    /**
     * Construct a new JarInfoTableModel.
     */
    public JarInfoTableModel()
    {
        m_columnNames = new String[] {
            m_res.getString("JarInfoTableModel.JarFileColumn"),
            m_res.getString("JarInfoTableModel.SizeColumn"),
            m_res.getString("JarInfoTableModel.SpecificationTitleColumn"),
            m_res.getString("JarInfoTableModel.SpecificationVersionColumn"),
            m_res.getString("JarInfoTableModel.SpecificationVendorColumn"),
            m_res.getString("JarInfoTableModel.ImplementationTitleColumn"),
            m_res.getString("JarInfoTableModel.ImplementationVersionColumn"),
            m_res.getString("JarInfoTableModel.ImplementationVendorColumn"),
        };

        m_data = new Object[0][0];
    }

    /**
     * Load the JarInfoTableModel with an array of JAR files.
     *
     * @param jarFiles The JAR files
     * @throws IOException Problem occurred getting JAR information
     */
    public void load(JarFile[] jarFiles) throws IOException
    {
        // Create one table row for each JAR file
        m_data = new Object[jarFiles.length][8];

        for (int iCnt=0; iCnt < jarFiles.length; iCnt++)
        {
            /* Get JAR info (jar file, size, spec title, spec version,
               spec title, impl title, impl version and impl
               vendor) */
            JarFile jarFile = jarFiles[iCnt];
            String sFile = jarFile.getName();
            File file = new File(sFile);

            // Some info comes from the manifest
            Manifest manifest = jarFile.getManifest();

            String sImplementationTitle = "";
            String sImplementationVersion = "";
            String sImplementationVendor = "";
            String sSpecificationTitle = "";
            String sSpecificationVersion = "";
            String sSpecificationVendor = "";

            if (manifest != null) // Manifest may not exist
            {
                Attributes attributes = manifest.getMainAttributes();

                String sValue = attributes.getValue("Specification-Title");
                if (sValue != null)
                {
                    sSpecificationTitle = sValue;
                }

                sValue = attributes.getValue("Specification-Version");
                if (sValue != null)
                {
                    sSpecificationVersion = sValue;
                }

                sValue = attributes.getValue("Specification-Vendor");
                if (sValue != null)
                {
                    sSpecificationVendor = sValue;
                }

                sValue = attributes.getValue("Implementation-Title");
                if (sValue != null)
                {
                    sImplementationTitle = sValue;
                }

                sValue = attributes.getValue("Implementation-Version");
                if (sValue != null)
                {
                    sImplementationVersion = sValue;
                }

                sValue = attributes.getValue("Implementation-Vendor");
                if (sValue != null)
                {
                    sImplementationVendor = sValue;
                }
            }

            // Populate the file column
            m_data[iCnt][0] = file.getName();

            // Populate the size column
            m_data[iCnt][1] = MessageFormat.format(
                m_res.getString("JarInfoTableModel.Size"),
                new Object[]{new Integer(Math.round(file.length() / 1024))});

            // Populate the implementation title column
            m_data[iCnt][2] = sSpecificationTitle;

            // Populate the implementation version column
            m_data[iCnt][3] = sSpecificationVersion;

            // Populate the implementation vendor column
            m_data[iCnt][4] = sSpecificationVendor;

            // Populate the specification title column
            m_data[iCnt][5] = sImplementationTitle;

            // Populate the specification version column
            m_data[iCnt][6] = sImplementationVersion;

            // Populate the specification vendor column
            m_data[iCnt][7] = sImplementationVendor;
        }

        fireTableDataChanged();
    }

    /**
     * Get the number of columns in the table.
     *
     * @return The number of columns
     */
    public int getColumnCount()
    {
        return m_columnNames.length;
    }

    /**
     * Get the number of rows in the table.
     *
     * @return The number of rows
     */
    public int getRowCount()
    {
        return m_data.length;
    }

    /**
     * Get the name of the column at the given position.
     *
     * @param iCol The column position
     * @return The column name
     */
    public String getColumnName(int iCol)
    {
        return m_columnNames[iCol];
    }

    /**
     * Get the cell value at the given row and column position.
     *
     * @param iRow The row position
     * @param iCol The column position
     * @return The cell value
     */
    public Object getValueAt(int iRow, int iCol)
    {
        return m_data[iRow][iCol];
    }

    /**
     * Get the class at of the cells at the given column position.
     *
     * @param iCol The column position
     * @return The column cells' class
     */
    public Class getColumnClass(int iCol)
    {
        return getValueAt(0, iCol).getClass();
    }

    /**
     * Is the cell at the given row and column position editable?
     *
     * @param iRow The row position
     * @param iCol The column position
     * @return True if the cell is editable, false otherwise
     */
    public boolean isCellEditable(int iRow, int iCol)
    {
        // The table is always read-only
        return false;
    }
}
