/*
 * KeyStoreTableModel.java
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
import javax.swing.table.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import net.sf.portecle.crypto.KeyStoreType;

/**
 * The table model used to display a KeyStore's entries sorted by alias name.
 */
class KeyStoreTableModel extends AbstractTableModel
{
    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Holds the column names */
    private String[] m_columnNames;

    /** Holds the table data */
    private Object[][] m_data;

    /** Value to place in the type column for a key pair entry */
    public static final String KEY_PAIR_ENTRY = m_res.getString("KeyStoreTableModel.KeyPairEntry");

    /** Value to place in the type column for a trusted certificate entry */
    public static final String TRUST_CERT_ENTRY = m_res.getString("KeyStoreTableModel.TrustCertEntry");

    /** Value to place in the type column for a key entry */
    public static final String KEY_ENTRY = m_res.getString("KeyStoreTableModel.KeyEntry");

    /**
     * Construct a new KeyStoreTableModel.
     */
    public KeyStoreTableModel()
    {
        m_columnNames = new String[3];
        m_columnNames[0] = m_res.getString("KeyStoreTableModel.TypeColumn");
        m_columnNames[1] = m_res.getString("KeyStoreTableModel.AliasColumn");
        m_columnNames[2] = m_res.getString("KeyStoreTableModel.LastModifiedDateColumn");

        m_data = new Object[0][0];
    }

    /**
     * Load the KeyStoreTableModel with the entries from a KeyStore.
     *
     * @param keyStore The KeyStore
     * @throws KeyStoreException A problem is encountered accessing the KeyStore's entries
     */
    public void load(KeyStore keyStore) throws KeyStoreException
    {
        Enumeration enum = keyStore.aliases();

        // Place aliases in a tree map to sort them
        TreeMap sortedAliases = new TreeMap();

        while (enum.hasMoreElements())
        {
            String sAlias = (String)enum.nextElement();
            sortedAliases.put(sAlias, sAlias);
        }

        // Create one table row for each KeyStore entry
        m_data = new Object[sortedAliases.size()][3];

        // Iterate through the sorted aliases, retrieving the KeyStore entries and populating the table model
        int iCnt=0;
        for (Iterator itr = sortedAliases.entrySet().iterator(); itr.hasNext(); iCnt++)
        {
            String sAlias = (String)((Map.Entry)itr.next()).getKey();

            // Populate the type column - it is set with an integer but a custom
            // cell renderer will cause a suitable icon to be displayed
            if (keyStore.isCertificateEntry(sAlias))
            {
                m_data[iCnt][0] = new String(TRUST_CERT_ENTRY);
            }
            else if ((keyStore.isKeyEntry(sAlias)) && (keyStore.getCertificateChain(sAlias) != null) &&
                     (keyStore.getCertificateChain(sAlias).length > 0))
            {
                m_data[iCnt][0] = new String(KEY_PAIR_ENTRY);
            }
            else
            {
                m_data[iCnt][0] = new String(KEY_ENTRY);
            }

            // Populate the alias column
            m_data[iCnt][1] = sAlias;

            // Populate the modified date column (if KeyStore type is not PKCS #12 - dates not supported)
            if (!keyStore.getType().equals(KeyStoreType.PKCS12.toString()))
            {
                m_data[iCnt][2] = keyStore.getCreationDate(sAlias);
            }
            else
            {
                m_data[iCnt][2] = ""; // Display empty string for modification date of PKCS #12 KeyStore entries
            }
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
