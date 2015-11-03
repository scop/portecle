/*
 * SingleFileDropHelper
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2010 Lam Chau, lamchau@gmail.com
 *             2011 Ville Skyttä, ville.skytta@iki.fi
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

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.dnd.InvalidDnDOperationException;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.TransferHandler;

/**
 * Drag and drop helper class that accepts single files.
 */
public class SingleFileDropHelper
    extends TransferHandler
{
	/** The usual flavor for dropped files */
	private static final DataFlavor FILE_FLAVOR = DataFlavor.javaFileListFlavor;

	/**
	 * text/uri-list flavor, used for example in Unix platforms
	 * 
	 * @see <a href="http://tools.ietf.org/html/rfc2483#section-5">RFC 2483</a>
	 */
	private static final DataFlavor URILIST_FLAVOR;

	static
	{
		DataFlavor flavor;
		try
		{
			flavor = new DataFlavor("text/uri-list;class=java.lang.String");
		}
		catch (ClassNotFoundException e)
		{
			flavor = null;
		}
		URILIST_FLAVOR = flavor;
	}

	protected File file;

	@Override
	public boolean canImport(TransferSupport support)
	{
		if (!support.isDrop())
		{
			return false;
		}

		try
		{
			List<File> files = getTransferFiles(support);
			if (files.size() == 1)
			{
				File aFile = files.get(0);
				if (aFile.isFile())
				{
					file = aFile.getAbsoluteFile();
					return true;
				}
			}
		}
		catch (InvalidDnDOperationException e)
		{
			// Workaround for known bug:
			// http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6759788
			return file != null;
		}
		catch (IOException e)
		{
			// Ignore this because getTransferable thinks we're going to use this object for something, we
			// really just want to check and show the user as soon as possible that the file (most likely a
			// directory) is not handled.
		}
		catch (UnsupportedFlavorException e)
		{
			// Ignore this because we've already explicitly defined which file types we'll support, it
			// shouldn't get here.
		}

		return false;
	}

	/**
	 * Get list of files from the given TransferSupport.
	 * 
	 * @param support the TransferSupport
	 * @return list of files
	 * @throws IOException
	 * @throws UnsupportedFlavorException
	 */
	private List<File> getTransferFiles(TransferSupport support)
	    throws IOException, UnsupportedFlavorException
	{
		ArrayList<File> files = new ArrayList<>();
		if (support.isDataFlavorSupported(FILE_FLAVOR))
		{
			Object data = support.getTransferable().getTransferData(FILE_FLAVOR);
			if (data instanceof List)
			{
				for (Object obj : (List<?>) data)
				{
					files.add(new File(obj.toString()));
				}
			}
		}
		else if (URILIST_FLAVOR != null && support.isDataFlavorSupported(URILIST_FLAVOR))
		{
			String data = (String) support.getTransferable().getTransferData(URILIST_FLAVOR);
			try (BufferedReader reader = new BufferedReader(new StringReader(data)))
			{
				String line;
				while ((line = reader.readLine()) != null)
				{
					if (!line.startsWith("#"))
					{
						try
						{
							files.add(new File(new URI(line)));
						}
						catch (IllegalArgumentException | URISyntaxException e)
						{
							// Ignored
						}
					}
				}
			}
		}
		return files;
	}
}
