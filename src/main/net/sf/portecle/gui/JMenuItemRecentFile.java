/*
 * JMenuItemRecentFile.java
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

import java.awt.event.KeyEvent;
import java.io.File;

import javax.swing.JMenuItem;

/**
 * A recent file menu item. Used in recent file menus (JMenuRecentFiles) to open files directly by activating a menu
 * item either through normal means or the mnemonic that reflects the menu items position in the list of recent files.
 * An action listener should be added to actually open the file. Other listeners can be added as required to respond to
 * other types of event.
 */
public class JMenuItemRecentFile
    extends JMenuItem
{
	/** Recent file */
	private final File m_fRecentFile;

	/**
	 * Menu's position in its recent file list (maintained by JMenuRecentFiles)
	 */
	private int m_iPosition;

	/**
	 * Construct a JMenuItemRecentFile.
	 * 
	 * @param fRecentFile The recent file
	 */
	public JMenuItemRecentFile(File fRecentFile)
	{
		super();

		m_fRecentFile = fRecentFile;
		setPosition(1);
	}

	/**
	 * Get the recent file.
	 * 
	 * @return The recent file
	 */
	public File getFile()
	{
		return m_fRecentFile;
	}

	/**
	 * Get the menu item's position in its recent file list (maintained by JMenuRecentFiles).
	 * 
	 * @return Position
	 */
	public int getPosition()
	{
		return m_iPosition;
	}

	/**
	 * Set the menu item's position in its recent file list (maintained by JMenuRecentFiles).
	 * 
	 * @param iPosition Position
	 */
	void setPosition(int iPosition)
	{
		m_iPosition = iPosition;
		setText(m_iPosition + " " + m_fRecentFile.getName());

		switch (m_iPosition)
		{
			case 1:
				super.setMnemonic(KeyEvent.VK_1);
				break;
			case 2:
				super.setMnemonic(KeyEvent.VK_2);
				break;
			case 3:
				super.setMnemonic(KeyEvent.VK_3);
				break;
			case 4:
				super.setMnemonic(KeyEvent.VK_4);
				break;
			case 5:
				super.setMnemonic(KeyEvent.VK_5);
				break;
			case 6:
				super.setMnemonic(KeyEvent.VK_6);
				break;
			case 7:
				super.setMnemonic(KeyEvent.VK_7);
				break;
			case 8:
				super.setMnemonic(KeyEvent.VK_8);
				break;
			case 9:
				super.setMnemonic(KeyEvent.VK_9);
				break;
		}
	}
}
