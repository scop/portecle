/*
 * RevokedCertsTableCellRend.java
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

package net.sf.portecle;

import java.awt.Component;
import java.math.BigInteger;
import java.text.DateFormat;
import java.util.Date;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * Custom cell renderer for the cells of the RevokedCerts table of DViewCRL.
 */
class RevokedCertsTableCellRend extends DefaultTableCellRenderer
{
    /**
     * Returns the rendered cell for the supplied entry type and column.
     *
     * @param jtRevokedCerts The JTable
     * @param value The value to assign to the cell
     * @param bIsSelected True if cell is selected
     * @param iRow The row of the cell to render
     * @param iCol The column of the cell to render
     * @param bHasFocus If true, render cell appropriately
     * @return The renderered cell
     */
    public Component getTableCellRendererComponent(
        JTable jtRevokedCerts, Object value, boolean bIsSelected,
        boolean bHasFocus, int iRow, int iCol)
    {
        JLabel cell = (JLabel) super.getTableCellRendererComponent(
            jtRevokedCerts, value, bIsSelected, bHasFocus, iRow, iCol);

        // Serial Number column - format to a hex string
        if (iCol == 0)
        {
            cell.setText(formatSerialNumber((BigInteger) value));
        }
        // Revocation Date column - format date
        else
        {
            // Include timezone
            cell.setText(
                DateFormat.getDateTimeInstance(
                    DateFormat.MEDIUM, DateFormat.LONG).format((Date) value));
        }

        cell.setBorder(new EmptyBorder(0, 5, 0, 5));

        return cell;
    }

    /**
     * Format the provided serial number into a hex string.  The string
     * is divided by spaces into groups of four hex characters.
     *
     * @param serialNumber Serial number
     * @return Formatted serial number
     */
    private String formatSerialNumber(BigInteger serialNumber)
    {
        String sHexSerialNumber = serialNumber.toString(16).toUpperCase();

        StringBuffer strBuff = new StringBuffer();

        for (int iCnt=0; iCnt < sHexSerialNumber.length(); iCnt++)
        {
            strBuff.append(sHexSerialNumber.charAt(iCnt));

            if (((iCnt+1) % 4) == 0 && iCnt+1 != sHexSerialNumber.length())
            {
                strBuff.append(' ');
            }
        }

        return strBuff.toString();
    }
}
