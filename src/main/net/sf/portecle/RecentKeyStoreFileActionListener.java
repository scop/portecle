/*
 * RecentKeyStoreFileActionListener.java
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

package net.sf.portecle;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

import javax.swing.JOptionPane;

/**
 * ActionListener intended for use with the net.sf.portecle.gui.JMenuItemRecentFile class. The ActionListener is used to
 * open a keystore file from the menu item.
 */
class RecentKeyStoreFileActionListener
    implements ActionListener
{
	/** Recent keystore file */
	private final File m_fRecentFile;

	/** FPortecle object that contains the recent files menu */
	private final FPortecle m_fPortecle;

	/**
	 * Create an RecentKeyStoreFileActionListener for the supplied keystore file and fPortecle frame.
	 * 
	 * @param fRecentFile Recent keystore file
	 * @param fPortecle FPortecle frame
	 */
	public RecentKeyStoreFileActionListener(File fRecentFile, FPortecle fPortecle)
	{
		m_fRecentFile = fRecentFile;
		m_fPortecle = fPortecle;
	}

	/**
	 * Action to perform to open the keystore file in response to an ActionEvent.
	 * 
	 * @param evt Action event
	 */
	@Override
	public void actionPerformed(ActionEvent evt)
	{
		m_fPortecle.setDefaultStatusBarText();

		// Does the current keystore contain unsaved changes?
		if (m_fPortecle.needSave())
		{
			// Yes - ask the user if it should be saved
			int iWantSave = m_fPortecle.wantSave();

			if (iWantSave == JOptionPane.YES_OPTION)
			{
				// Save it
				if (!m_fPortecle.saveKeyStore())
				{
					return; // Save failed
				}
			}
			else if (iWantSave == JOptionPane.CANCEL_OPTION)
			{
				return;
			}
		}
		m_fPortecle.openKeyStoreFile(m_fRecentFile, true);
	}
}
