/*
 * ExtensionsTableModel.java
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

import java.security.cert.X509Extension;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.TreeMap;

import javax.swing.table.AbstractTableModel;

import net.sf.portecle.crypto.X509Ext;

/**
 * The table model used to display X.509 extensions.
 */
class ExtensionsTableModel
    extends AbstractTableModel
{
	/** Column names */
	private static final String[] COLUMN_NAMES;
	static
	{
		ResourceBundle rb = ResourceBundle.getBundle("net/sf/portecle/resources");

		COLUMN_NAMES =
		    new String[] { rb.getString("ExtensionsTableModel.CriticalColumn"),
		        rb.getString("ExtensionsTableModel.NameColumn"),
		        rb.getString("ExtensionsTableModel.OidColumn") };
	}

	/** Column classes */
	private static final Class<?>[] COLUMN_CLASSES = { Boolean.class, String.class, String.class };

	/** Holds the table data */
	private Object[][] m_data;

	/**
	 * Construct a new ExtensionsTableModel.
	 */
	public ExtensionsTableModel()
	{
		m_data = new Object[0][getColumnCount()];
	}

	/**
	 * Load the ExtensionsTableModel with X.509 extensions.
	 * 
	 * @param extensions The X.509 extensions
	 */
	public void load(X509Extension extensions)
	{
		// Get extension OIDs
		Set<String> critExts = extensions.getCriticalExtensionOIDs();
		Set<String> nonCritExts = extensions.getNonCriticalExtensionOIDs();

		// Rows will be sorted by extension name by default
		TreeMap<String, X509Ext> sortedExts = new TreeMap<String, X509Ext>();

		// Add extensions to sorted map of extensions

		// First the critical extensions...
		for (String sExtOid : critExts)
		{
			byte[] bValue = extensions.getExtensionValue(sExtOid);

			X509Ext ext = new X509Ext(sExtOid, bValue, true);

			sortedExts.put(ext.getName(), ext);
		}

		// ...then the critical extensions
		for (String sExtOid : nonCritExts)
		{
			byte[] bValue = extensions.getExtensionValue(sExtOid);

			X509Ext ext = new X509Ext(sExtOid, bValue, false);

			sortedExts.put(ext.getName(), ext);
		}

		// Create one table row for each extension
		m_data = new Object[sortedExts.size()][getColumnCount()];

		// Load rows in extension name order from tree map
		int iCnt = 0;
		for (X509Ext ext : sortedExts.values())
		{
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
		int col = 0;

		// Populate the Critical columnsExtname
		m_data[iRow][col++] = extension.isCriticalExtension();

		// Populate the Name column
		m_data[iRow][col++] = extension.getName();

		// Populate the OID column
		m_data[iRow][col++] = extension.getOid();
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
		return COLUMN_NAMES[iCol];
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
