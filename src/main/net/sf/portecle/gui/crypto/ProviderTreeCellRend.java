/*
 * ProviderTreeCellRend.java
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

package net.sf.portecle.gui.crypto;

import static net.sf.portecle.FPortecle.RB;

import java.awt.Component;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.TreeNode;

/**
 * Custom cell renderer for the cells of the DProviderInfo tree.
 */
class ProviderTreeCellRend
    extends DefaultTreeCellRenderer
{
	/**
	 * Returns the rendered cell for the supplied value.
	 * 
	 * @param jtrProvider The JTree
	 * @param value The value to assign to the cell
	 * @param bIsSelected True if cell is selected
	 * @param bIsExpanded True if cell is expanded
	 * @param bLeaf True if cell is a leaf
	 * @param iRow The row of the cell to render
	 * @param bHasFocus If true, render cell appropriately
	 * @return The rendered cell
	 */
	@Override
	public Component getTreeCellRendererComponent(JTree jtrProvider, Object value, boolean bIsSelected,
	    boolean bIsExpanded, boolean bLeaf, int iRow, boolean bHasFocus)
	{
		JLabel cell = (JLabel) super.getTreeCellRendererComponent(jtrProvider, value, bIsSelected, bIsExpanded, bLeaf,
		    iRow, bHasFocus);
		cell.setText(value.toString());

		// Sanity check of value
		if (value instanceof DefaultMutableTreeNode)
		{
			// Get the correct icon for the node and set any tool tip text
			DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;

			ImageIcon icon = null;

			if (node.getLevel() == 0)
			{
				// Root node
				icon = new ImageIcon(getClass().getResource(RB.getString("ProviderTreeCellRend.Root.image")));
				cell.setToolTipText(RB.getString("ProviderTreeCellRend.Root.tooltip"));
			}
			else if (node.getLevel() == 1)
			{
				// Provider node
				icon = new ImageIcon(getClass().getResource(RB.getString("ProviderTreeCellRend.Provider.image")));
				cell.setToolTipText(RB.getString("ProviderTreeCellRend.Provider.tooltip"));
			}
			else if (node.getLevel() == 2)
			{
				TreeNode parent = node.getParent();
				int iIndex = parent.getIndex(node);

				if (iIndex == 0)
				{
					// Provider description node
					icon =
					    new ImageIcon(getClass().getResource(RB.getString("ProviderTreeCellRend.Description.image")));
					cell.setToolTipText(RB.getString("ProviderTreeCellRend.Description.tooltip"));
				}
				else if (iIndex == 1)
				{
					// Provider version node
					icon = new ImageIcon(getClass().getResource(RB.getString("ProviderTreeCellRend.Version.image")));
					cell.setToolTipText(RB.getString("ProviderTreeCellRend.Version.tooltip"));
				}
				else
				{
					// Provider properties node
					icon = new ImageIcon(getClass().getResource(RB.getString("ProviderTreeCellRend.Properties.image")));
					cell.setToolTipText(RB.getString("ProviderTreeCellRend.Properties.tooltip"));
				}
			}
			else
			{
				// Provider property node
				icon = new ImageIcon(getClass().getResource(RB.getString("ProviderTreeCellRend.Property.image")));
				cell.setToolTipText(RB.getString("ProviderTreeCellRend.Property.tooltip"));
			}

			// Set the icon
			cell.setIcon(icon);
		}

		return cell;
	}
}
