/*
 * RevokedCertsTableCellRend.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2008 Ville Skyttä, ville.skytta@iki.fi
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

import java.awt.Component;
import java.awt.Font;
import java.text.DateFormat;
import java.util.Date;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * Custom cell renderer for the cells of the RevokedCerts table of DViewCRL.
 */
class RevokedCertsTableCellRend
    extends DefaultTableCellRenderer
{
	/** Cached monospace font instance */
	private final Font monospace;

	/**
	 * Creates a new revoked certificates table cell renderer.
	 * 
	 * @param table Parent table
	 */
	public RevokedCertsTableCellRend(JTable table)
	{
		monospace = new Font(Font.MONOSPACED, Font.PLAIN, table.getFont().getSize());
	}

	/**
	 * Returns the rendered cell for the supplied entry type and column.
	 * 
	 * @param jtRevokedCerts The JTable
	 * @param value The value to assign to the cell
	 * @param bIsSelected True if cell is selected
	 * @param iRow The row of the cell to render
	 * @param iCol The column of the cell to render
	 * @param bHasFocus If true, render cell appropriately
	 * @return The rendered cell
	 */
	@Override
	public Component getTableCellRendererComponent(JTable jtRevokedCerts, Object value, boolean bIsSelected,
	    boolean bHasFocus, int iRow, int iCol)
	{
		JLabel cell =
		    (JLabel) super.getTableCellRendererComponent(jtRevokedCerts, value, bIsSelected, bHasFocus, iRow, iCol);

		// Serial Number column - format to a hex string
		if (iCol == 0)
		{
			cell.setFont(monospace);
			cell.setText(StringUtil.toHex(value, 4, " ").toString());
		}
		// Revocation Date column - format date
		else
		{
			// Include time zone
			cell.setText(DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.LONG).format((Date) value));
		}

		cell.setBorder(new EmptyBorder(0, 5, 0, 5));

		return cell;
	}
}
