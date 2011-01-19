/*
 * DesktopUtil.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2008 Ville Skyttä, ville.skytta@iki.fi
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

import static net.sf.portecle.FPortecle.RB;

import java.awt.Component;
import java.awt.Desktop;
import java.net.URI;
import java.net.URLEncoder;
import java.text.MessageFormat;

import javax.swing.JOptionPane;

/**
 * Desktop utilities.
 */
public final class DesktopUtil
{
	/** Desktop */
	private static final Desktop DESKTOP = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;

	/** Not needed. */
	private DesktopUtil()
	{
		// Nothing to do
	}

	/**
	 * Open URI in system default browser.
	 * 
	 * @param parentComponent
	 * @param uri URI to open
	 * @see Desktop#browse(URI)
	 */
	public static void browse(Component parentComponent, URI uri)
	{
		if (DESKTOP != null)
		{
			try
			{
				DESKTOP.browse(uri);
				return;
			}
			catch (Exception e)
			{
				// Ignored
			}
		}

		// Could not launch - tell the user the address
		JOptionPane.showMessageDialog(parentComponent,
		    MessageFormat.format(RB.getString("FPortecle.NoLaunchBrowser.message"), uri),
		    RB.getString("FPortecle.Title"), JOptionPane.INFORMATION_MESSAGE);
	}

	/**
	 * Open mail compose window in system default mail client.
	 * 
	 * @param parentComponent
	 * @param address E-mail address to mail to
	 * @see Desktop#mail(URI)
	 */
	public static void mail(Component parentComponent, String address)
	{
		if (DESKTOP != null)
		{
			try
			{
				DESKTOP.mail(new URI("mailto:" + URLEncoder.encode(address, "ISO-8859-1")));
				return;
			}
			catch (Exception e)
			{
				// Ignored
			}
		}

		// Could not launch - tell the user the address
		JOptionPane.showMessageDialog(parentComponent,
		    MessageFormat.format(RB.getString("FPortecle.NoLaunchEmail.message"), address),
		    RB.getString("FPortecle.Title"), JOptionPane.INFORMATION_MESSAGE);
	}
}
