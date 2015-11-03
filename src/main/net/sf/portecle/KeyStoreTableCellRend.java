/*
 * KeyStoreTableTypeCellRend.java
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

import static net.sf.portecle.FPortecle.RB;

import java.awt.Component;
import java.text.DateFormat;
import java.util.Date;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * Custom cell renderer for the cells of the keystore table of FPortecle.
 */
class KeyStoreTableCellRend
    extends DefaultTableCellRenderer
{
	/**
	 * Returns the rendered cell for the supplied value and column.
	 * 
	 * @param jtKeyStore The JTable
	 * @param value The value to assign to the cell
	 * @param bIsSelected True if cell is selected
	 * @param iRow The row of the cell to render
	 * @param iCol The column of the cell to render
	 * @param bHasFocus If true, render cell appropriately
	 * @return The rendered cell
	 */
	@Override
	public Component getTableCellRendererComponent(JTable jtKeyStore, Object value, boolean bIsSelected,
	    boolean bHasFocus, int iRow, int iCol)
	{
		JLabel cell =
		    (JLabel) super.getTableCellRendererComponent(jtKeyStore, value, bIsSelected, bHasFocus, iRow, iCol);

		// Entry column - display an icon representing the type and tool tip text
		if (iCol == 0)
		{
			ImageIcon icon = null;

			if (KeyStoreTableModel.KEY_PAIR_ENTRY.equals(value))
			{
				icon = new ImageIcon(getClass().getResource(RB.getString("KeyStoreTableCellRend.KeyPairEntry.image")));
				cell.setToolTipText(RB.getString("KeyStoreTableCellRend.KeyPairEntry.tooltip"));
			}
			else if (KeyStoreTableModel.TRUST_CERT_ENTRY.equals(value))
			{
				icon =
				    new ImageIcon(getClass().getResource(RB.getString("KeyStoreTableCellRend.TrustCertEntry.image")));
				cell.setToolTipText(RB.getString("KeyStoreTableCellRend.TrustCertEntry.tooltip"));
			}
			else
			{
				icon = new ImageIcon(getClass().getResource(RB.getString("KeyStoreTableCellRend.KeyEntry.image")));
				cell.setToolTipText(RB.getString("KeyStoreTableCellRend.KeyEntry.tooltip"));
			}

			cell.setIcon(icon);
			cell.setText("");
			cell.setVerticalAlignment(CENTER);
			cell.setHorizontalAlignment(CENTER);
		}
		// Last Modified column - format date (if date supplied)
		else if (iCol == 2)
		{
			if (value != null)
			{
				if (value instanceof Date)
				{
					// Include time zone
					cell.setText(
					    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.LONG).format((Date) value));
				}
				else
				{
					cell.setText(value.toString());
				}
			}
		}
		// Alias column - just use alias text
		else
		{
			cell.setText(value.toString());
		}

		cell.setBorder(new EmptyBorder(0, 5, 0, 5));

		return cell;
	}
}
