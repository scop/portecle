/*
 * StatusBar.java
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

/**
 * Interface for a status bar. Used with the StatusBarChangeHandler to support the placing and removal of help messages
 * into the status bar as menu items are selected/de-selected.
 */
public interface StatusBar
{
	/**
	 * Display the supplied text in the status bar.
	 * 
	 * @param sStatus Text to display
	 */
	void setStatusBarText(String sStatus);

	/**
	 * Set the status bar text to its default message.
	 */
	void setDefaultStatusBarText();

}
