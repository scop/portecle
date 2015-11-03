/*
 * ExtensionsTableCellRend.java
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

package net.sf.portecle;

import static net.sf.portecle.FPortecle.RB;

import java.awt.Component;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * Custom cell renderer for the cells of the Extensions table of DViewExtensions.
 */
class ExtensionsTableCellRend
    extends DefaultTableCellRenderer
{
	/**
	 * Returns the rendered cell for the supplied entry type and column.
	 * 
	 * @param jtExtensions The JTable
	 * @param value The value to assign to the cell
	 * @param bIsSelected True if cell is selected
	 * @param iRow The row of the cell to render
	 * @param iCol The column of the cell to render
	 * @param bHasFocus If true, render cell appropriately
	 * @return The rendered cell
	 */
	@Override
	public Component getTableCellRendererComponent(JTable jtExtensions, Object value, boolean bIsSelected,
	    boolean bHasFocus, int iRow, int iCol)
	{
		JLabel cell =
		    (JLabel) super.getTableCellRendererComponent(jtExtensions, value, bIsSelected, bHasFocus, iRow, iCol);

		// Critical column - display an icon representing criticality and tool tip text
		if (iCol == 0)
		{
			ImageIcon icon = null;

			if (((Boolean) value))
			{
				icon = new ImageIcon(
				    getClass().getResource(RB.getString("ExtensionsTableCellRend.CriticalExtension.image")));
				cell.setToolTipText(RB.getString("ExtensionsTableCellRend.CriticalExtension.tooltip"));
			}
			else
			{
				icon = new ImageIcon(
				    getClass().getResource(RB.getString("ExtensionsTableCellRend." + "NonCriticalExtension.image")));
				cell.setToolTipText(RB.getString("ExtensionsTableCellRend." + "NonCriticalExtension.tooltip"));
			}

			cell.setIcon(icon);
			cell.setText("");
			cell.setVerticalAlignment(CENTER);
			cell.setHorizontalAlignment(CENTER);
		}
		else
		{
			// Just use toString of object as text
			cell.setText(value.toString());
		}

		cell.setBorder(new EmptyBorder(0, 5, 0, 5));

		return cell;
	}
}
