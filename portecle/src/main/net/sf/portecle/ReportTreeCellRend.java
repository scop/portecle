/*
 * ReportTreeCellRend.java
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

import java.util.ResourceBundle;
import java.awt.Component;
import javax.swing.*;
import javax.swing.tree.*;

/**
 * Custom cell renderer for the cells of the DKeyStoreReport tree.
 */
class ReportTreeCellRend extends DefaultTreeCellRenderer
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/resources");

    /**
     * Returns the rendered cell for the supplied value.
     *
     * @param jtrReport The JTree
     * @param value The value to assign to the cell
     * @param bIsSelected True if cell is selected
     * @param bIsExpanded True if cell is expanded
     * @param bLeaf True if cell is a leaf
     * @param iRow The row of the cell to render
     * @param bHasFocus If true, render cell appropriately
     * @return The renderered cell
     */
    public Component getTreeCellRendererComponent(
        JTree jtrReport, Object value, boolean bIsSelected,
        boolean bIsExpanded, boolean bLeaf, int iRow, boolean bHasFocus)
    {
        JLabel cell = (JLabel) super.getTreeCellRendererComponent(
            jtrReport, value, bIsSelected, bIsExpanded, bLeaf, iRow, bHasFocus
            );
        cell.setText(value.toString());
        ImageIcon icon = null;

        // Sanity check of value
        if (value instanceof DefaultMutableTreeNode)
        {
            // Set the cell's icon and tool tip text - depends on
            // nodes depth and index

            DefaultMutableTreeNode node = (DefaultMutableTreeNode)value;

            int iLevel = node.getLevel();

            TreeNode parent = node.getParent();
            int iIndex = 0;
            if (parent != null)
            {
                iIndex = parent.getIndex(node);
            }

            if (iLevel == 0)
            {
                icon = new ImageIcon(
                    getClass().getResource(
                        m_res.getString("ReportTreeCellRend.Root.image")));
                cell.setToolTipText(
                    m_res.getString("ReportTreeCellRend.Root.tooltip"));
            }
            else if (iLevel == 1)
            {
                Object obj = node.getUserObject();

                if (obj instanceof Entry)
                {
                    Entry entry = (Entry)obj;

                    if (entry.isKey())
                    {
                        icon = new ImageIcon(
                            getClass().getResource(
                                m_res.getString(
                                    "ReportTreeCellRend.KeyEntry.image")));
                        cell.setToolTipText(
                            m_res.getString(
                                "ReportTreeCellRend.KeyEntry.tooltip"));
                    }
                    else if (entry.isKeyPair())
                    {
                        icon = new ImageIcon(
                            getClass().getResource(
                                m_res.getString(
                                    "ReportTreeCellRend.KeyPairEntry.image")));
                        cell.setToolTipText(
                            m_res.getString(
                                "ReportTreeCellRend.KeyPairEntry.tooltip"));
                    }
                    else
                    {
                        icon = new ImageIcon(
                            getClass().getResource(
                                m_res.getString(
                                    "ReportTreeCellRend.TrustCertEntry.image")
                                ));
                        cell.setToolTipText(
                            m_res.getString(
                                "ReportTreeCellRend.TrustCertEntry.tooltip"));
                    }
                }
            }
            else if (iLevel == 2)
            {
                // PKCS #12 KeyStores will not have a created node
                if (iIndex == 0 && node.getChildCount() == 0)
                {
                    icon = new ImageIcon(
                        getClass().getResource(
                            m_res.getString(
                                "ReportTreeCellRend.Created.image")));
                    cell.setToolTipText(
                        m_res.getString("ReportTreeCellRend.Created.tooltip"));
                }
                else
                {
                    icon = new ImageIcon(
                        getClass().getResource(
                            m_res.getString(
                                "ReportTreeCellRend.Certificates.image")));
                    cell.setToolTipText(
                        m_res.getString(
                            "ReportTreeCellRend.Certificates.tooltip"));
                }
            }
            else if (iLevel == 3)
            {
                icon = new ImageIcon(
                    getClass().getResource(
                        m_res.getString(
                            "ReportTreeCellRend.Certificate.image")));
                cell.setToolTipText(
                    m_res.getString("ReportTreeCellRend.Certificate.tooltip"));
            }
            else
            {
                if (iIndex == 0)
                {
                    icon = new ImageIcon(
                        getClass().getResource(
                            m_res.getString(
                                "ReportTreeCellRend.Version.image")));
                    cell.setToolTipText(
                        m_res.getString("ReportTreeCellRend.Version.tooltip"));
                }
                else if (iIndex == 1)
                {
                    icon = new ImageIcon(
                        getClass().getResource(
                            m_res.getString(
                                "ReportTreeCellRend.Subject.image")));
                    cell.setToolTipText(
                        m_res.getString("ReportTreeCellRend.Subject.tooltip"));
                }
                else if (iIndex == 2)
                {
                    icon = new ImageIcon(
                        getClass().getResource(
                            m_res.getString(
                                "ReportTreeCellRend.Issuer.image")));
                    cell.setToolTipText(
                        m_res.getString("ReportTreeCellRend.Issuer.tooltip"));
                }
                else if (iIndex == 3)
                {
                    icon = new ImageIcon(
                        getClass().getResource(
                            m_res.getString(
                                "ReportTreeCellRend.SerialNumber.image")));
                    cell.setToolTipText(
                        m_res.getString(
                            "ReportTreeCellRend.SerialNumber.tooltip"));
                }
                else if (iIndex == 4)
                {
                    icon = new ImageIcon(
                        getClass().getResource(
                            m_res.getString(
                                "ReportTreeCellRend.ValidFrom.image")));
                    cell.setToolTipText(
                        m_res.getString(
                            "ReportTreeCellRend.ValidFrom.tooltip"));
                }
                else if (iIndex == 5)
                {
                    icon = new ImageIcon(
                        getClass().getResource(
                            m_res.getString(
                                "ReportTreeCellRend.ValidTo.image")));
                    cell.setToolTipText(
                        m_res.getString("ReportTreeCellRend.ValidTo.tooltip"));
                }
                else if (iIndex == 6)
                {
                    icon = new ImageIcon(
                        getClass().getResource(
                            m_res.getString(
                                "ReportTreeCellRend.PublicKey.image")));
                    cell.setToolTipText(
                        m_res.getString(
                            "ReportTreeCellRend.PublicKey.tooltip"));
                }
                else if (iIndex == 7)
                {
                    icon = new ImageIcon(
                        getClass().getResource(
                            m_res.getString(
                                "ReportTreeCellRend.SignatureAlgorithm.image")
                            ));
                    cell.setToolTipText(
                        m_res.getString(
                            "ReportTreeCellRend.SignatureAlgorithm.tooltip"));
                }
                else if (iIndex == 8)
                {
                    icon = new ImageIcon(
                        getClass().getResource(
                            m_res.getString(
                                "ReportTreeCellRend.Md5Fingerprint.image")));
                    cell.setToolTipText(
                        m_res.getString(
                            "ReportTreeCellRend.Md5Fingerprint.tooltip"));
                }
                else
                {
                    icon = new ImageIcon(
                        getClass().getResource(
                            m_res.getString(
                                "ReportTreeCellRend.Sha1Fingerprint.image")));
                    cell.setToolTipText(
                        m_res.getString(
                            "ReportTreeCellRend.Sha1Fingerprint.tooltip"));
                }
            }

            // Set the icon
            cell.setIcon(icon);
        }

        return cell;
    }

    /**
     * Simple class used to distinguish between KeyStore entry types
     * passed to 1the cell renderer.  The renderer uses the type to
     * set the cell's icon and tool top text and the alais to display
     * as it's text.
     */
    static class Entry extends Object
    {
        /** Entry type */
        private int m_iType;

        /** Entry alias */
        private String m_sAlias;

        /** Key entry type */
        private static final int KEY = 0;

        /** Key pair entry type */
        private static final int KEY_PAIR = 1;

        /** Trusted certificate entry type */
        private static final int TRUSTED_CERTIFICATE = 2;

        /**
         * Construct an entry.
         *
         * @param iType Entry type
         * @param sAlias Entry alias
         */
        private Entry(int iType, String sAlias)
        {
            m_iType = iType;
            m_sAlias = sAlias;
        }

        /**
         * Get a key entry.
         *
         * @param sAlias Entry alias
         * @return Key entry
         */
        public static Entry getKeyInstance(String sAlias)
        {
            return new Entry(KEY, sAlias);
        }

        /**
         * Get a key pair entry.
         *
         * @param sAlias Entry alias
         * @return Key pair entry
         */
        public static Entry getKeyPairInstance(String sAlias)
        {
            return new Entry(KEY_PAIR, sAlias);
        }

        /**
         * Get a trsuted certificate entry.
         *
         * @param sAlias Entry alias
         * @return Trusted certificate entry
         */
        public static Entry getTrustedCertificateInstance(String sAlias)
        {
            return new Entry(TRUSTED_CERTIFICATE, sAlias);
        }

        /**
         * Is entry of type key?
         *
         * @return True if it is, false otherwise.
         */
        public boolean isKey()
        {
            if (m_iType == KEY)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /**
         * Is entry of type key pair?
         *
         * @return True if it is, false otherwise.
         */
        public boolean isKeyPair()
        {
            if (m_iType == KEY_PAIR)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /**
         * Is entry of type trusted certificate?
         *
         * @return True if it is, false otherwise.
         */
        public boolean isTrustedCertificate()
        {
            if (m_iType == TRUSTED_CERTIFICATE)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /**
         * Returns the entry alias.  Value displayed by renderer.
         *
         * @return Entry alias
         */
        public String toString()
        {
            return m_sAlias;
        }
    }
}
