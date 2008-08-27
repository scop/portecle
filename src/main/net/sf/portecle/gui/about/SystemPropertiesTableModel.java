/*
 * SystemPropertiesTableModel.java
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

package net.sf.portecle.gui.about;

import java.util.Enumeration;
import java.util.Map;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.TreeMap;

import javax.swing.table.AbstractTableModel;

/**
 * The table model used to System Properties.
 */
class SystemPropertiesTableModel
    extends AbstractTableModel
{
	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/gui/about/resources");

	/** Holds the column names */
	private String[] m_columnNames;

	/** Holds the table data */
	private Object[][] m_data;

	/**
	 * Construct a new SystemPropertiesTableModel.
	 */
	public SystemPropertiesTableModel()
	{
		m_columnNames =
		    new String[] { m_res.getString("SystemPropertiesTableModel.NameColumn"),
		        m_res.getString("SystemPropertiesTableModel.ValueColumn"), };

		m_data = new Object[0][0];
	}

	/**
	 * Load the SystemPropertiesTableModel with System Properties.
	 */
	public void load()
	{
		// Get system properties
		Properties sysProps = System.getProperties();
		TreeMap<String, String> sortedSysProps = new TreeMap<String, String>();

		// Place properties in a sorted map
		for (Enumeration<?> names = sysProps.propertyNames(); names.hasMoreElements();)
		{
			String sName = (String) names.nextElement();
			String sValue = sysProps.getProperty(sName);

			// Convert line.separator property value to be printable
			if (sName.equals("line.separator"))
			{
				StringBuilder sbValue = new StringBuilder();
				for (int iCnt = 0; iCnt < sValue.length(); iCnt++)
				{
					if (sValue.charAt(iCnt) == '\r')
					{
						sbValue.append("\\r");
					}
					else if (sValue.charAt(iCnt) == '\n')
					{
						sbValue.append("\\n");
					}
					else
					{
						sbValue.append(sValue);
					}
				}
				sValue = sbValue.toString();
			}

			sortedSysProps.put(sName, sValue);
		}

		// Create one table row per property
		m_data = new Object[sortedSysProps.size()][getColumnCount()];

		// Load sorted properties into the table
		int iCnt = 0;
		for (Map.Entry<String, String> property : sortedSysProps.entrySet())
		{
			// Name column
			m_data[iCnt][0] = property.getKey();

			// Value column
			m_data[iCnt][1] = property.getValue();

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
		return getValueAt(0, iCol).getClass();
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
