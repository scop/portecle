/*
 * JarInfoTableModel.java
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

package net.sf.portecle.gui.jar;

import java.io.File;
import java.io.IOException;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import javax.swing.table.AbstractTableModel;

import net.sf.portecle.FPortecle;

/**
 * The table model used to display information about JAR files.
 */
class JarInfoTableModel
    extends AbstractTableModel
{
	/** Column names */
	private static final String[] COLUMN_NAMES = { FPortecle.RB.getString("JarInfoTableModel.JarFileColumn"),
	    FPortecle.RB.getString("JarInfoTableModel.SizeColumn"),
	    FPortecle.RB.getString("JarInfoTableModel.SpecificationTitleColumn"),
	    FPortecle.RB.getString("JarInfoTableModel.SpecificationVersionColumn"),
	    FPortecle.RB.getString("JarInfoTableModel.SpecificationVendorColumn"),
	    FPortecle.RB.getString("JarInfoTableModel.ImplementationTitleColumn"),
	    FPortecle.RB.getString("JarInfoTableModel.ImplementationVersionColumn"),
	    FPortecle.RB.getString("JarInfoTableModel.ImplementationVendorColumn") };

	/** Column classes */
	private static final Class<?>[] COLUMN_CLASSES = { String.class, Long.class, String.class, String.class,
	    String.class, String.class, String.class, String.class };

	/** Holds the table data */
	private Object[][] m_data;

	/**
	 * Construct a new JarInfoTableModel.
	 */
	public JarInfoTableModel()
	{
		m_data = new Object[0][getColumnCount()];
	}

	/**
	 * Load the JarInfoTableModel with an array of JAR files.
	 * 
	 * @param jarFiles The JAR files
	 * @throws IOException Problem occurred getting JAR information
	 */
	public void load(JarFile[] jarFiles)
	    throws IOException
	{
		// Create one table row for each JAR file
		m_data = new Object[jarFiles.length][getColumnCount()];

		for (int iCnt = 0; iCnt < jarFiles.length; iCnt++)
		{
			/*
			 * Get JAR info (jar file, size, specification title, specification version, specification title,
			 * implementation title, implementation version and implementation vendor)
			 */
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

			int col = 0;

			// Populate the file column
			m_data[iCnt][col++] = file.getName();

			// Populate the size column
			m_data[iCnt][col++] = file.length();

			// Populate the implementation title column
			m_data[iCnt][col++] = sSpecificationTitle;

			// Populate the implementation version column
			m_data[iCnt][col++] = sSpecificationVersion;

			// Populate the implementation vendor column
			m_data[iCnt][col++] = sSpecificationVendor;

			// Populate the specification title column
			m_data[iCnt][col++] = sImplementationTitle;

			// Populate the specification version column
			m_data[iCnt][col++] = sImplementationVersion;

			// Populate the specification vendor column
			m_data[iCnt][col++] = sImplementationVendor;
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
