/*
 * IntegerDocumentFilter.java
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

import java.awt.Toolkit;

import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;

/**
 * Document filter for non-negative integer only input.
 */
public class IntegerDocumentFilter
    extends DocumentMaxLengthFilter
{
	/**
	 * Create a new integer document filter.
	 * 
	 * @param maxLength maximum accepted document length
	 */
	public IntegerDocumentFilter(int maxLength)
	{
		super(maxLength);
	}

	@Override
	public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr)
	    throws BadLocationException
	{
		if (string == null || string.isEmpty())
		{
			// Always allow empty inserts
			super.insertString(fb, offset, string, attr);
			return;
		}

		boolean accepted;
		try
		{
			accepted = (Integer.parseInt(string) >= 0);
		}
		catch (NumberFormatException e)
		{
			accepted = false;
		}

		if (!accepted)
		{
			Toolkit.getDefaultToolkit().beep();
			return;
		}

		super.insertString(fb, offset, string, attr);
	}

	@Override
	public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attrs)
	    throws BadLocationException
	{
		if (text == null || text.isEmpty())
		{
			// Always allow removal
			super.replace(fb, offset, length, text, attrs);
			return;
		}

		boolean accepted;
		try
		{
			accepted = (Integer.parseInt(text) >= 0);
		}
		catch (NumberFormatException e)
		{
			accepted = false;
		}

		if (!accepted)
		{
			Toolkit.getDefaultToolkit().beep();
			return;
		}

		super.replace(fb, offset, length, text, attrs);
	}
}
