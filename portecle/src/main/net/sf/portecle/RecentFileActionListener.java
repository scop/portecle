/*
 * RecentFileActionListener.java
 *
 * Copyright (C) 2004 Wayne Grant
 * waynedgrant@hotmail.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * (This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

package net.sf.portecle;

import java.io.*;
import java.awt.event.*;
import javax.swing.*;

/**
 * ActionListener intended for use with the
 * net.sf.portecle.gui.JMenuItemRecentFile class.
 * The ActionListener is used to open a file from the menu item.
 */
class RecentFileActionListener implements ActionListener
{
    /** Recent KeyStore file */
    File m_fRecentFile;

    /** FKeyToolGUI object that contains the recent files menu */
    FKeyToolGUI m_fKeyToolGui;

    /**
     * Create an RecentFileActionListener for the supplied KeyStore file
     * and fKeyToolGui frame.
     *
     * @param fRecentFile Recent KeyStore file
     * @param fKeyToolGui FKeyToolGUI frame
     */
    public RecentFileActionListener(File fRecentFile, FKeyToolGUI fKeyToolGui)
    {
        m_fRecentFile = fRecentFile;
        m_fKeyToolGui = fKeyToolGui;
    }

    /**
     * Action to perform to open the KeyStore file in response to an ActionEvent.
     *
     * @param evt Action event
     */
    public void actionPerformed(ActionEvent evt)
    {
        m_fKeyToolGui.setDefaultStatusBarText();

        // Does the current KeyStore contain unsaved changes?
        if (m_fKeyToolGui.needSave())
        {
            // Yes - ask the user if it should be saved
            int iWantSave = m_fKeyToolGui.wantSave();

            if (iWantSave == JOptionPane.YES_OPTION)
            {
                // Save it
                if (!m_fKeyToolGui.saveKeyStore())
                {
                    return; // Save failed
                }
            }
            else if (iWantSave == JOptionPane.CANCEL_OPTION)
            {
                return;
            }
        }
        m_fKeyToolGui.openKeyStore(m_fRecentFile);
    }
}
