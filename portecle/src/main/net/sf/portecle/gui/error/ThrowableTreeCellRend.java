/*
 * ThrowableTreeCellRend.java
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

package net.sf.portecle.gui.error;

import java.awt.Component;
import java.util.ResourceBundle;

import javax.swing.*;
import javax.swing.tree.*;

/**
 * Custom cell renderer for the cells of the DThrowableDetail tree.
 */
class ThrowableTreeCellRend extends DefaultTreeCellRenderer
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/gui/error/resources");

    /**
     * Returns the rendered cell for the supplied value.
     *
     * @param jtrThrowable The JTree
     * @param value The value to assign to the cell
     * @param bIsSelected True if cell is selected
     * @param bIsExpanded True if cell is expanded
     * @param bLeaf True if cell is a leaf
     * @param iRow The row of the cell to render
     * @param bHasFocus If true, render cell appropriately
     * @return The renderered cell
     */

    public Component getTreeCellRendererComponent(
        JTree jtrThrowable, Object value, boolean bIsSelected,
        boolean bIsExpanded, boolean bLeaf, int iRow, boolean bHasFocus)
    {
        JLabel cell = (JLabel) super.getTreeCellRendererComponent(
            jtrThrowable, value, bIsSelected, bIsExpanded, bLeaf, iRow,
            bHasFocus);
        cell.setText(value.toString());

        // Sanity check of value
        if (value instanceof DefaultMutableTreeNode)
        {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode)value;
            Object userValue = node.getUserObject();
            ImageIcon icon = null;

            // Each node type has a different icon and tool tip text
            if (userValue instanceof Throwable)
            {
                // Throwable
                icon = new ImageIcon(
                    getClass().getResource(
                        m_res.getString(
                            "ThrowableTreeCellRend.Throwable.image")));
                cell.setToolTipText(
                    m_res.getString(
                        "ThrowableTreeCellRend.Throwable.tooltip"));
            }
            else if (userValue instanceof StackTraceElement)
            {
                // Stack trace element
                icon = new ImageIcon(
                    getClass().getResource(
                        m_res.getString(
                            "ThrowableTreeCellRend.StackTrace.image")));
                cell.setToolTipText(
                    m_res.getString(
                        "ThrowableTreeCellRend.StackTrace.tooltip"));
            }
            else
            {
                // Root node
                icon = new ImageIcon(
                    getClass().getResource(
                        m_res.getString("ThrowableTreeCellRend.Root.image")));
                cell.setToolTipText(
                    m_res.getString("ThrowableTreeCellRend.Root.tooltip"));
            }

            cell.setIcon(icon);
        }

        return cell;
    }
}
