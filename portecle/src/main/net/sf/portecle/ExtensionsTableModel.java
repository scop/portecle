/*
 * ExtensionsTableModel.java
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
import java.security.cert.X509Extension;
import javax.swing.table.*;
import net.sf.portecle.crypto.X509Ext;

/**
 * The table model used to display X.509 extensions.
 */
class ExtensionsTableModel extends AbstractTableModel
{
    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Holds the column names */
    private String[] m_columnNames;

    /** Holds the table data */
    private Object[][] m_data;

    /**
     * Construct a new ExtensionsTableModel.
     */
    public ExtensionsTableModel()
    {
        m_columnNames = new String[3];
        m_columnNames[0] = m_res.getString("ExtensionsTableModel.CriticalColumn");
        m_columnNames[1] = m_res.getString("ExtensionsTableModel.NameColumn");
        m_columnNames[2] = m_res.getString("ExtensionsTableModel.OidColumn");

        m_data = new Object[0][0];
    }

    /**
     * Load the ExtensionsTableModel with X.509 extensions.
     *
     * @param extensions The X.509 extensions
     */
    public void load(X509Extension extensions)
    {
        // Get extension OIDs
        Set critExts = extensions.getCriticalExtensionOIDs();
        Set nonCritExts = extensions.getNonCriticalExtensionOIDs();

        // Rows will be sorted by extension name
        TreeMap sortedExts = new TreeMap();

        // Add extensions to sorted map of extensions

        // First the critical extensions...
        for (Iterator itr = critExts.iterator(); itr.hasNext();)
        {
            String sExtOid = (String)itr.next();
            byte[] bValue = extensions.getExtensionValue(sExtOid);

            X509Ext ext = new X509Ext(sExtOid, bValue, true);

            // Name may be null if extension unrecognised
            String sExtName = ext.getName();
            if (sExtName == null)
            {
                sExtName = "";
            }

            sortedExts.put(sExtName, ext);
        }

        // ...then the critical extensions
        for (Iterator itr = nonCritExts.iterator(); itr.hasNext();)
        {
            String sExtOid = (String)itr.next();
            byte[] bValue = extensions.getExtensionValue(sExtOid);

            X509Ext ext = new X509Ext(sExtOid, bValue, false);

            // Name may be null if extension unrecognised
            String sExtName = ext.getName();
            if (sExtName == null)
            {
                sExtName = "";
            }

            sortedExts.put(sExtName, ext);
        }

        // Create one table row for each extension
        m_data = new Object[sortedExts.size()][3];

        // Load rows in extension name order from tree map
        int iCnt = 0;
        for (Iterator itrSortedExts = sortedExts.entrySet().iterator(); itrSortedExts.hasNext();)
        {
            X509Ext ext = (X509Ext)((Map.Entry)itrSortedExts.next()).getValue();
            loadRow(ext, iCnt);
            iCnt++;
        }

        fireTableDataChanged();
    }

    /**
     * Load the ExtensionsTableModel with an X.509 extension.
     *
     * @param extension The X.509 extension
     * @param iRow The row to add extension to
     */
    private void loadRow(X509Ext extension, int iRow)
    {
        // Populate the Critical columnsExtname
        m_data[iRow][0] = new Boolean(extension.isCriticalExtension());

        // Populate the Name column
        String sName = extension.getName();

        if (sName == null)
        {
            m_data[iRow][1] = "-";
        }
        else
        {
            m_data[iRow][1] = sName;
        }

        // Populate the OID column
        m_data[iRow][2] = extension.getOid();
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
