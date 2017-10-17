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

import java.awt.*;
import java.util.logging.Logger;

import static java.lang.Class.forName;

public class AppleApplicationHelper
{

	private static final Logger LOG = Logger.getLogger(AppleApplicationHelper.class.getCanonicalName());

	public boolean isAppleEnvironment()
	{
		try
		{
			forName("com.apple.eawt.Application");
			return true;
		}
		catch (ClassNotFoundException e)
		{
			return false;
		}
	}

	public void setDockIconImage(Image image)
	{
		try
		{
			Class applicationClass = forName("com.apple.eawt.Application");
			Object application = applicationClass.getMethod("getApplication").invoke(applicationClass);
			applicationClass.getMethod("setDockIconImage", Image.class).invoke(application, image);
		}
		catch (Exception e)
		{
			LOG.finer("Skipping to set application dock icon for Mac OS X, because didn't found 'com.apple.eawt.Application' class. Exception: " + e.getMessage());
		}
	}
}