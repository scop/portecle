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
import javax.swing.text.DocumentFilter;

/**
 * Document filter for non-negative integer only input.
 */
public class IntegerDocumentFilter
    extends DocumentFilter
{
	/** Maximum accepted value length */
	private final int maxLength;

	/**
	 * Create a new integer document filter.
	 * 
	 * @param maxLength maximum accepted document length
	 */
	public IntegerDocumentFilter(int maxLength)
	{
		this.maxLength = maxLength;
	}

	@Override
	public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr)
	    throws BadLocationException
	{
		int strLen;
		if (string == null || (strLen = string.length()) == 0)
		{
			// Always allow empty inserts
			super.insertString(fb, offset, string, attr);
			return;
		}

		boolean accepted = false;
		try
		{
			Integer parsed = Integer.valueOf(string);
			accepted = (fb.getDocument().getLength() + strLen <= maxLength && parsed >= 0);
		}
		catch (NumberFormatException ignored)
		{
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
		int textLen;
		if (text == null || (textLen = text.length()) == 0)
		{
			// Always allow removal
			super.replace(fb, offset, length, text, attrs);
			return;
		}

		boolean accepted = false;
		try
		{
			int parsed = Integer.valueOf(text);

			int numAdded = textLen - length;
			accepted = (parsed >= 0 && fb.getDocument().getLength() + numAdded <= maxLength);
		}
		catch (NumberFormatException ignored)
		{
		}

		if (!accepted)
		{
			Toolkit.getDefaultToolkit().beep();
			return;
		}

		super.replace(fb, offset, length, text, attrs);
	}
}
