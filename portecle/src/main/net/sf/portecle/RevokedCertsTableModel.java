/*
 * RevokedCertsTableModel.java
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package net.sf.portecle;

import java.security.cert.X509CRLEntry;
import java.util.Iterator;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.TreeMap;

import javax.swing.table.AbstractTableModel;

/**
 * The table model used to display an array of X.509 CRL entries
 * sorted by serial number.
 */
class RevokedCertsTableModel extends AbstractTableModel
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Holds the column names */
    private String[] m_columnNames;

    /** Holds the table data */
    private Object[][] m_data;

    /**
     * Construct a new RevokedCertsTableModel.
     */
    public RevokedCertsTableModel()
    {
        m_columnNames = new String[] {
            m_res.getString("RevokedCertsTableModel.SerialNumberColumn"),
            m_res.getString("RevokedCertsTableModel.RevocationDateColumn"),
        };

        m_data = new Object[0][0];
    }

    /**
     * Load the RevokedCertsTableModel with an array of X.509 CRL entries.
     *
     * @param revokedCerts The X.509 CRL entries
     */
    public void load(X509CRLEntry[] revokedCerts)
    {
        // Place revoked certs in a tree map to sort them by serial number
        TreeMap sortedRevokedCerts = new TreeMap();

        for (int iCnt=0; iCnt < revokedCerts.length; iCnt++)
        {
            sortedRevokedCerts.put(revokedCerts[iCnt].getSerialNumber(),
                                   revokedCerts[iCnt]);
        }

        // Create one table row for each revoked certificate
        m_data = new Object[sortedRevokedCerts.size()][2];

        // Iterate through the sorted revoked certificates populating
        // the table model
        int iCnt=0;
        for (Iterator itr = sortedRevokedCerts.entrySet().iterator();
             itr.hasNext(); iCnt++)
        {
            X509CRLEntry x509CrlEntry =
                (X509CRLEntry) ((Map.Entry) itr.next()).getValue();

            // Populate the serial number column
            m_data[iCnt][0] = x509CrlEntry.getSerialNumber();

            // Populate the modified date column
            m_data[iCnt][1] = x509CrlEntry.getRevocationDate();
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
