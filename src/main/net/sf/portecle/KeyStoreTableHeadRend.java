/*
 * KeyStoreTableTypeHeadRend.java
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
import javax.swing.border.BevelBorder;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * Custom cell renderer for the headers of the keystore table of FPortecle.
 */
class KeyStoreTableHeadRend
    extends DefaultTableCellRenderer
{
	/**
	 * Returns the rendered header cell for the supplied value and column.
	 *
	 * @param jtKeyStore The JTable
	 * @param value The value to assign to the cell
	 * @param bIsSelected True if cell is selected
	 * @param iRow The row of the cell to render
	 * @param iCol The column of the cell to render
	 * @param bHasFocus If true, render cell appropriately *
	 * @return The rendered cell
	 */
	@Override
	public Component getTableCellRendererComponent(JTable jtKeyStore, Object value, boolean bIsSelected,
	    boolean bHasFocus, int iRow, int iCol)
	{
		// Get header renderer
		JLabel header = (JLabel) jtKeyStore.getColumnModel().getColumn(iCol).getHeaderRenderer();

		// The entry type header contains an icon
		if (iCol == KeyStoreTableModel.COLUMN_TYPE)
		{
			header.setText("");
			ImageIcon icon =
			    new ImageIcon(getClass().getResource(RB.getString("KeyStoreTableHeadRend.TypeColumn.image")));
			header.setIcon(icon);
			header.setHorizontalAlignment(CENTER);
			header.setVerticalAlignment(CENTER);

			header.setToolTipText(RB.getString("KeyStoreTableHeadRend.TypeColumn.tooltip"));
		}
		// The expiration header contains an icon
		else if (iCol == KeyStoreTableModel.COLUMN_EXPIRATION)
		{
			header.setText("");
			ImageIcon icon =
			    new ImageIcon(getClass().getResource(RB.getString("KeyStoreTableHeadRend.CertExpirationColumn.image")));
			header.setIcon(icon);
			header.setHorizontalAlignment(CENTER);
			header.setVerticalAlignment(CENTER);
			
			header.setToolTipText(RB.getString("KeyStoreTableHeadRend.ExpiredColumn.tooltip"));
		}
		// The other headers contain text
		else
		{
			header.setText((String) value);
			header.setHorizontalAlignment(LEFT);

			if (iCol == KeyStoreTableModel.COLUMN_ALIAS)
			{
				header.setToolTipText(RB.getString("KeyStoreTableHeadRend.AliasColumn.tooltip"));
			}
			else if (iCol == KeyStoreTableModel.COLUMN_DATELASTMODIFIED)
			{
				header.setToolTipText(RB.getString("KeyStoreTableHeadRend.LastModifiedDateColumn.tooltip"));
			}
		}

		header.setBorder(new CompoundBorder(new BevelBorder(BevelBorder.RAISED), new EmptyBorder(0, 5, 0, 5)));

		return header;
	}
}
