/*
 * KeyStoreTableModel.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2008 Ville Skyttä, ville.skytta@iki.fi
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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Date;
import java.util.Enumeration;
import java.util.ResourceBundle;
import java.util.TreeMap;

import javax.swing.table.AbstractTableModel;

import net.sf.portecle.crypto.KeyStoreType;

/**
 * The table model used to display a keystore's entries sorted by alias name.
 */
class KeyStoreTableModel
    extends AbstractTableModel
{
	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

	/** Value to place in the type column for a key pair entry */
	public static String KEY_PAIR_ENTRY = m_res.getString("KeyStoreTableModel.KeyPairEntry");

	/** Value to place in the type column for a trusted certificate entry */
	public static String TRUST_CERT_ENTRY = m_res.getString("KeyStoreTableModel.TrustCertEntry");

	/** Value to place in the type column for a key entry */
	public static String KEY_ENTRY = m_res.getString("KeyStoreTableModel.KeyEntry");

	/** Holds the column names */
	private final String[] m_columnNames;

	/** Holds the table data */
	private Object[][] m_data;

	/** Column classes */
	private static final Class<?>[] COLUMN_CLASSES = new Class<?>[3];
	static
	{
		COLUMN_CLASSES[0] = String.class;
		COLUMN_CLASSES[1] = String.class;
		COLUMN_CLASSES[2] = Date.class;
	}

	/**
	 * Construct a new KeyStoreTableModel.
	 */
	public KeyStoreTableModel()
	{
		m_columnNames =
		    new String[] { m_res.getString("KeyStoreTableModel.TypeColumn"),
		        m_res.getString("KeyStoreTableModel.AliasColumn"),
		        m_res.getString("KeyStoreTableModel.LastModifiedDateColumn"), };

		m_data = new Object[0][getColumnCount()];
	}

	/**
	 * Load the KeyStoreTableModel with the entries from a keystore.
	 * 
	 * @param keyStore The keystore
	 * @throws KeyStoreException A problem is encountered accessing the keystore's entries
	 */
	public void load(KeyStore keyStore)
	    throws KeyStoreException
	{
		// Place aliases in a tree map to sort them
		TreeMap<String, String> sortedAliases = new TreeMap<String, String>();
		for (Enumeration<String> en = keyStore.aliases(); en.hasMoreElements();)
		{
			String sAlias = en.nextElement();
			sortedAliases.put(sAlias, sAlias);
		}

		boolean cdSupport = KeyStoreType.valueOf(keyStore.getType()).isEntryCreationDateUseful();

		// Create one table row for each keystore entry
		m_data = new Object[sortedAliases.size()][getColumnCount()];

		// Iterate through the sorted aliases, retrieving the keystore
		// entries and populating the table model
		int iCnt = 0;
		for (String sAlias : sortedAliases.keySet())
		{
			// Populate the type column - it is set with an integer
			// but a custom cell renderer will cause a suitable icon
			// to be displayed
			if (keyStore.isCertificateEntry(sAlias))
			{
				m_data[iCnt][0] = TRUST_CERT_ENTRY;
			}
			else if (keyStore.isKeyEntry(sAlias) && keyStore.getCertificateChain(sAlias) != null &&
			    keyStore.getCertificateChain(sAlias).length != 0)
			{
				m_data[iCnt][0] = KEY_PAIR_ENTRY;
			}
			else
			{
				m_data[iCnt][0] = KEY_ENTRY;
			}

			// Populate the alias column
			m_data[iCnt][1] = sAlias;

			// Populate the modified date column
			if (cdSupport)
			{
				m_data[iCnt][2] = keyStore.getCreationDate(sAlias);
			}

			iCnt++;
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
		return COLUMN_CLASSES.length;
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
	@Override
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
	@Override
	public Class<?> getColumnClass(int iCol)
	{
		return COLUMN_CLASSES[iCol];
	}

	/**
	 * Is the cell at the given row and column position editable?
	 * 
	 * @param iRow The row position
	 * @param iCol The column position
	 * @return True if the cell is editable, false otherwise
	 */
	@Override
	public boolean isCellEditable(int iRow, int iCol)
	{
		// The table is always read-only
		return false;
	}
}
