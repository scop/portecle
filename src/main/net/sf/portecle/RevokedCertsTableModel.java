/*
 * RevokedCertsTableModel.java
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

import java.math.BigInteger;
import java.security.cert.X509CRLEntry;
import java.util.Date;

import javax.swing.table.AbstractTableModel;

/**
 * The table model used to display an array of X.509 CRL entries.
 */
class RevokedCertsTableModel
    extends AbstractTableModel
{
	/** Column names */
	private static final String[] COLUMN_NAMES = { FPortecle.RB.getString("RevokedCertsTableModel.SerialNumberColumn"),
	    FPortecle.RB.getString("RevokedCertsTableModel.RevocationDateColumn") };

	/** Column classes */
	private static final Class<?>[] COLUMN_CLASSES = { BigInteger.class, Date.class };

	/** Holds the table data */
	private Object[][] m_data;

	/**
	 * Construct a new RevokedCertsTableModel.
	 */
	public RevokedCertsTableModel()
	{
		m_data = new Object[0][getColumnCount()];
	}

	/**
	 * Load the RevokedCertsTableModel with an array of X.509 CRL entries.
	 * 
	 * @param revokedCerts The X.509 CRL entries
	 */
	public void load(X509CRLEntry[] revokedCerts)
	{
		// Create one table row for each revoked certificate
		m_data = new Object[revokedCerts.length][getColumnCount()];

		// Iterate through the sorted revoked certificates populating the table model
		int iCnt = 0;
		for (X509CRLEntry x509CrlEntry : revokedCerts)
		{
			int col = 0;

			// Populate the serial number column
			m_data[iCnt][col++] = x509CrlEntry.getSerialNumber();

			// Populate the modified date column
			m_data[iCnt][col++] = x509CrlEntry.getRevocationDate();

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
}
