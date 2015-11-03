/*
 * JMenuRecentFiles.java
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
import java.util.ArrayList;

import javax.swing.JMenu;

/**
 * Menu with Recent File List capability, i.e. a list of files where the most recently accessed file is set as the first
 * item shifting other files down and the list contains no duplicates. Note: only call the add(JMenuItemRecentFile) to
 * add recent file menu items when the menu is completely populated with standard menu items and separators.
 */
public class JMenuRecentFiles
    extends JMenu
{
	/** Maximum length of list */
	private static final int MAX_LENGTH = 9;

	/** Recent file list menu items */
	private final JMenuItemRecentFile[] m_jmirf;

	/** Index in menu to show recent file menu items */
	private final int m_iIndex;

	/**
	 * Construct a JMenuRecentFiles.
	 * 
	 * @param sTitle Title of menu
	 * @param iLength Length of recent files list to maintain
	 * @param iIndex Index in menu to show recent file menu items
	 */
	public JMenuRecentFiles(String sTitle, int iLength, int iIndex)
	{
		super(sTitle);

		m_jmirf = new JMenuItemRecentFile[Math.min(iLength, MAX_LENGTH)];
		m_iIndex = iIndex;
	}

	/**
	 * Remove all recent file menu items from the menu.
	 */
	private void removeAllRecentFiles()
	{
		for (int iCnt = 0; iCnt < m_jmirf.length; iCnt++)
		{
			if (m_jmirf[iCnt] == null)
			{
				break;
			}

			remove(m_jmirf[iCnt]);
		}
	}

	/**
	 * Add all recent file menu items to the menu.
	 */
	private void addAllRecentFiles()
	{
		for (int iCnt = 0; iCnt < m_jmirf.length; iCnt++)
		{
			if (m_jmirf[iCnt] == null)
			{
				break;
			}
			add(m_jmirf[iCnt], m_iIndex + iCnt + 1);
		}
	}

	/**
	 * Does the menu have any recent files?
	 * 
	 * @return True if the menu has recent files, false otherwise
	 */
	private boolean recentFiles()
	{
		boolean bNoRecentFiles = true;

		for (int iCnt = 0; iCnt < m_jmirf.length; iCnt++)
		{
			if (m_jmirf[iCnt] != null)
			{
				bNoRecentFiles = false;
				break;
			}
		}
		return !bNoRecentFiles;
	}

	/**
	 * Find the recent files array index of the supplied file.
	 * 
	 * @param fRecent Recent file to find
	 * @return The array index of the recent file of -1 if there is none
	 */
	private int findRecentFile(File fRecent)
	{
		int iIndex = -1;

		for (int iCnt = 0; iCnt < m_jmirf.length; iCnt++)
		{
			if (m_jmirf[iCnt] == null)
			{
				break;
			}

			if (fRecent.equals(m_jmirf[iCnt].getFile()))
			{
				iIndex = iCnt;
				break;
			}
		}
		return iIndex;
	}

	/**
	 * Add a recent file menu item to the menu. Only call when the menu is completely populated with standard menu items
	 * and separators.
	 * 
	 * @param jmirfNew The new recent file menu item
	 */
	public void add(JMenuItemRecentFile jmirfNew)
	{
		// No items exist yet so add leading separator
		if (!recentFiles())
		{
			insertSeparator(m_iIndex);
		}

		int iIndex = findRecentFile(jmirfNew.getFile());

		// Menu item already exists at first position
		if (iIndex == 0)
		{
			// Do nothing
			return;
		}

		// Remove all recent menu items from the menu
		removeAllRecentFiles();

		// Set position of new menu item to start of list (i.e. position 1)
		jmirfNew.setPosition(1);

		// Item already exists outside of first position
		if (iIndex != -1)
		{
			// Introduce it to the first position and move the others up over its old position
			for (int iCnt = 0; iCnt <= iIndex; iCnt++)
			{
				JMenuItemRecentFile jmirfTmp = m_jmirf[iCnt];
				m_jmirf[iCnt] = jmirfNew;
				jmirfNew = jmirfTmp;
				jmirfNew.setPosition(iCnt + 2);
			}
		}
		// Item does not exist in the menu
		else
		{
			// Introduce new item to the start of the list and shift the others up one
			for (int iCnt = 0; iCnt < m_jmirf.length; iCnt++)
			{
				JMenuItemRecentFile jmirfTmp = m_jmirf[iCnt];
				m_jmirf[iCnt] = jmirfNew;
				jmirfNew = jmirfTmp;

				if (jmirfNew == null)
				{
					break; // Done shifting
				}
				jmirfNew.setPosition(iCnt + 2);
			}
		}

		// Reintroduce reorganized recent menu items to the menu
		addAllRecentFiles();
	}

	/**
	 * Get the set of recent files currently maintained by the menu in order.
	 * 
	 * @return The recent files
	 */
	public File[] getRecentFiles()
	{
		ArrayList<File> arrList = new ArrayList<>();

		for (JMenuItemRecentFile rf : m_jmirf)
		{
			if (rf == null)
			{
				break;
			}

			arrList.add(rf.getFile());
		}

		return arrList.toArray(new File[arrList.size()]);
	}
}
