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

import javax.swing.table.AbstractTableModel;

import net.sf.portecle.crypto.KeyStoreType;

/**
 * The table model used to display a keystore's entries sorted by alias name.
 */
class KeyStoreTableModel
    extends AbstractTableModel
{
	/** Column names */
	private static final String[] COLUMN_NAMES = { FPortecle.RB.getString("KeyStoreTableModel.TypeColumn"),
	    FPortecle.RB.getString("KeyStoreTableModel.AliasColumn"),
	    FPortecle.RB.getString("KeyStoreTableModel.LastModifiedDateColumn") };

	/** Value to place in the type column for a key pair entry */
	public static final String KEY_PAIR_ENTRY = FPortecle.RB.getString("KeyStoreTableModel.KeyPairEntry");

	/** Value to place in the type column for a trusted certificate entry */
	public static final String TRUST_CERT_ENTRY = FPortecle.RB.getString("KeyStoreTableModel.TrustCertEntry");

	/** Value to place in the type column for a key entry */
	public static final String KEY_ENTRY = FPortecle.RB.getString("KeyStoreTableModel.KeyEntry");

	/** Column classes */
	private static final Class<?>[] COLUMN_CLASSES = { String.class, String.class, Date.class };

	/** Holds the table data */
	private Object[][] m_data;

	/** Parent Portecle object */
	private final FPortecle portecle;

	/**
	 * Construct a new KeyStoreTableModel.
	 */
	public KeyStoreTableModel(FPortecle portecle)
	{
		m_data = new Object[0][getColumnCount()];
		this.portecle = portecle;
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
		// Does the keystore support creation dates?
		boolean cdSupport = KeyStoreType.valueOfType(keyStore.getType()).isEntryCreationDateUseful();

		// Create one table row for each keystore entry
		m_data = new Object[keyStore.size()][getColumnCount()];

		// Iterate through the aliases, retrieving the keystore entries and populating the table model
		int iCnt = 0;
		for (Enumeration<String> en = keyStore.aliases(); en.hasMoreElements();)
		{
			String sAlias = en.nextElement();

			// Populate the type column - it is set with an integer but a custom cell renderer will cause a
			// suitable icon to be displayed
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
	@Override
	public int getColumnCount()
	{
		return COLUMN_CLASSES.length;
	}

	/**
	 * Get the number of rows in the table.
	 * 
	 * @return The number of rows
	 */
	@Override
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
		return COLUMN_NAMES[iCol];
	}

	/**
	 * Get the cell value at the given row and column position.
	 * 
	 * @param iRow The row position
	 * @param iCol The column position
	 * @return The cell value
	 */
	@Override
	public Object getValueAt(int iRow, int iCol)
	{
		return m_data[iRow][iCol];
	}

	@Override
	public void setValueAt(Object value, int rowIndex, int columnIndex)
	{
		if (isCellEditable(rowIndex, columnIndex))
		{
			portecle.renameEntry(m_data[rowIndex][columnIndex].toString(), value.toString(), true);
		}
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
		if (iCol != 1)
		{
			return false;
		}

		// Key-only entries are not renameable - we do a remove-store operation but the KeyStore API won't
		// allow us to store a PrivateKey without associated certificate chain.
		// TODO: Maybe it'd work for other Key types? Need testing material.
		return !KEY_ENTRY.equals(m_data[iRow][0]);
	}
}
