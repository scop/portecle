/*
 * StatusBarChangeHandler.java
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

package net.sf.portecle.gui.statusbar;

import javax.swing.JMenuItem;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

/**
 * Handles change events on a menu item that causes the status bar text
 * to show or hide help text for the menu item.
 */
public class StatusBarChangeHandler
    implements ChangeListener
{
    /** Menu item */
    private JMenuItem m_jmi;

    /** Help text for the menu item */
    private String m_sHelpText;

    /** The status bar */
    private StatusBar m_statusBar;

    /**
     * Construct a StatusBarChangeHandler.
     *
     * @param jmi The menu item
     * @param sHelpText Help text for the menu item
     * @param statusBar The status bar
     */
    public StatusBarChangeHandler(JMenuItem jmi, String sHelpText,
        StatusBar statusBar)
    {
        m_jmi = jmi;
        m_sHelpText = sHelpText;
        m_statusBar = statusBar;
        m_jmi.addChangeListener(this);
    }

    /**
     * Menu item's state has changed - if armed show its help text, otherwise
     * hide any help text.
     *
     * @param evt The change event
     */
    public void stateChanged(ChangeEvent evt)
    {
        if (m_jmi.isArmed()) {
            // Display help text
            m_statusBar.setStatusBarText(m_sHelpText);
        }
        else {
            // Display default status
            m_statusBar.setDefaultStatusBarText();
        }
    }
}
