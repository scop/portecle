/*
 * FileExtFilter.java
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

package net.sf.portecle.gui;

import java.io.File;

import javax.swing.filechooser.FileFilter;

/**
 * File filter specifically for filtering against file extensions.
 */
public class FileExtFilter
    extends FileFilter
{
	/** File extensions to filter against */
	private final String[] m_sExts;

	/** Collective description of the set of extensions */
	private final String m_sDescription;

	/**
	 * Construct a FileExtFilter for a single file extension.
	 * 
	 * @param sExt The file extension (e.g. "exe" for a Windows executable)
	 * @param sDescription Short description of the file extension
	 */
	public FileExtFilter(String sExt, String sDescription)
	{
		m_sExts = new String[] { sExt };
		m_sDescription = sDescription;
	}

	/**
	 * Construct a FileExtFilter for a set of related file extension.
	 * 
	 * @param sExts The file extension (e.g. "exe" for a Windows executable)
	 * @param sDescription Short collective description for the file extensions
	 */
	public FileExtFilter(String[] sExts, String sDescription)
	{
		m_sExts = new String[sExts.length];
		System.arraycopy(sExts, 0, m_sExts, 0, m_sExts.length);
		m_sDescription = sDescription;
	}

	/**
	 * Does the supplied file match the filter?
	 * 
	 * @param file The file to filter
	 * @return True if the file matches the filter, false otherwise
	 */
	@Override
	public boolean accept(File file)
	{
		if (file.isDirectory())
		{
			return true;
		}

		String sFileExt = getExtension(file);

		if (sFileExt == null)
		{
			return false;
		}

		for (String sExt : m_sExts)
		{
			if (sFileExt.equalsIgnoreCase(sExt))
			{
				return true;
			}
		}
		return false;
	}

	/**
	 * Get the description.
	 * 
	 * @return The description
	 */
	@Override
	public String getDescription()
	{
		return m_sDescription;
	}

	/**
	 * Get the supplied file's extension.
	 * 
	 * @param file The file
	 * @return The file's extension
	 */
	private String getExtension(File file)
	{
		String sExt = null;
		String sName = file.getName();
		int i = sName.lastIndexOf('.');

		if (i > 0 && i < sName.length() - 1)
		{
			sExt = sName.substring(i + 1).toLowerCase();
		}
		return sExt;
	}
}
