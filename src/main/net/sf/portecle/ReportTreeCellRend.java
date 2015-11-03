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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package net.sf.portecle;

import static net.sf.portecle.FPortecle.RB;

import java.awt.Component;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.TreeNode;

/**
 * Custom cell renderer for the cells of the DKeyStoreReport tree.
 */
class ReportTreeCellRend
    extends DefaultTreeCellRenderer
{
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
	 * @return The rendered cell
	 */
	@Override
	public Component getTreeCellRendererComponent(JTree jtrReport, Object value, boolean bIsSelected,
	    boolean bIsExpanded, boolean bLeaf, int iRow, boolean bHasFocus)
	{
		JLabel cell = (JLabel) super.getTreeCellRendererComponent(jtrReport, value, bIsSelected, bIsExpanded, bLeaf,
		    iRow, bHasFocus);
		cell.setText(value.toString());
		ImageIcon icon = null;

		// Sanity check of value
		if (value instanceof DefaultMutableTreeNode)
		{
			// Set the cell's icon and tool tip text - depends on nodes depth and index

			DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;

			int iLevel = node.getLevel();

			TreeNode parent = node.getParent();
			int iIndex = 0;
			if (parent != null)
			{
				iIndex = parent.getIndex(node);
			}

			if (iLevel == 0)
			{
				icon = new ImageIcon(getClass().getResource(RB.getString("ReportTreeCellRend.Root.image")));
				cell.setToolTipText(RB.getString("ReportTreeCellRend.Root.tooltip"));
			}
			else if (iLevel == 1)
			{
				Object obj = node.getUserObject();

				if (obj instanceof Entry)
				{
					Entry entry = (Entry) obj;

					if (entry.isKey())
					{
						icon = new ImageIcon(getClass().getResource(RB.getString("ReportTreeCellRend.KeyEntry.image")));
						cell.setToolTipText(RB.getString("ReportTreeCellRend.KeyEntry.tooltip"));
					}
					else if (entry.isKeyPair())
					{
						icon = new ImageIcon(
						    getClass().getResource(RB.getString("ReportTreeCellRend.KeyPairEntry.image")));
						cell.setToolTipText(RB.getString("ReportTreeCellRend.KeyPairEntry.tooltip"));
					}
					else
					{
						icon = new ImageIcon(
						    getClass().getResource(RB.getString("ReportTreeCellRend.TrustCertEntry.image")));
						cell.setToolTipText(RB.getString("ReportTreeCellRend.TrustCertEntry.tooltip"));
					}
				}
			}
			else if (iLevel == 2)
			{
				// PKCS #12 keystores will not have a created node
				if (iIndex == 0 && node.getChildCount() == 0)
				{
					icon = new ImageIcon(getClass().getResource(RB.getString("ReportTreeCellRend.Created.image")));
					cell.setToolTipText(RB.getString("ReportTreeCellRend.Created.tooltip"));
				}
				else
				{
					icon = new ImageIcon(getClass().getResource(RB.getString("ReportTreeCellRend.Certificates.image")));
					cell.setToolTipText(RB.getString("ReportTreeCellRend.Certificates.tooltip"));
				}
			}
			else if (iLevel == 3)
			{
				icon = new ImageIcon(getClass().getResource(RB.getString("ReportTreeCellRend.Certificate.image")));
				cell.setToolTipText(RB.getString("ReportTreeCellRend.Certificate.tooltip"));
			}
			else
			{
				if (iIndex == 0)
				{
					icon = new ImageIcon(getClass().getResource(RB.getString("ReportTreeCellRend.Version.image")));
					cell.setToolTipText(RB.getString("ReportTreeCellRend.Version.tooltip"));
				}
				else if (iIndex == 1)
				{
					icon = new ImageIcon(getClass().getResource(RB.getString("ReportTreeCellRend.Subject.image")));
					cell.setToolTipText(RB.getString("ReportTreeCellRend.Subject.tooltip"));
				}
				else if (iIndex == 2)
				{
					icon = new ImageIcon(getClass().getResource(RB.getString("ReportTreeCellRend.Issuer.image")));
					cell.setToolTipText(RB.getString("ReportTreeCellRend.Issuer.tooltip"));
				}
				else if (iIndex == 3)
				{
					icon = new ImageIcon(getClass().getResource(RB.getString("ReportTreeCellRend.SerialNumber.image")));
					cell.setToolTipText(RB.getString("ReportTreeCellRend.SerialNumber.tooltip"));
				}
				else if (iIndex == 4)
				{
					icon = new ImageIcon(getClass().getResource(RB.getString("ReportTreeCellRend.ValidFrom.image")));
					cell.setToolTipText(RB.getString("ReportTreeCellRend.ValidFrom.tooltip"));
				}
				else if (iIndex == 5)
				{
					icon = new ImageIcon(getClass().getResource(RB.getString("ReportTreeCellRend.ValidTo.image")));
					cell.setToolTipText(RB.getString("ReportTreeCellRend.ValidTo.tooltip"));
				}
				else if (iIndex == 6)
				{
					icon = new ImageIcon(getClass().getResource(RB.getString("ReportTreeCellRend.PublicKey.image")));
					cell.setToolTipText(RB.getString("ReportTreeCellRend.PublicKey.tooltip"));
				}
				else if (iIndex == 7)
				{
					icon = new ImageIcon(
					    getClass().getResource(RB.getString("ReportTreeCellRend.SignatureAlgorithm.image")));
					cell.setToolTipText(RB.getString("ReportTreeCellRend.SignatureAlgorithm.tooltip"));
				}
				else if (iIndex == 8)
				{
					icon =
					    new ImageIcon(getClass().getResource(RB.getString("ReportTreeCellRend.Sha1Fingerprint.image")));
					cell.setToolTipText(RB.getString("ReportTreeCellRend.Sha1Fingerprint.tooltip"));
				}
				else
				{
					icon =
					    new ImageIcon(getClass().getResource(RB.getString("ReportTreeCellRend.Md5Fingerprint.image")));
					cell.setToolTipText(RB.getString("ReportTreeCellRend.Md5Fingerprint.tooltip"));
				}
			}

			// Set the icon
			cell.setIcon(icon);
		}

		return cell;
	}

	/**
	 * Simple class used to distinguish between keystore entry types passed to 1the cell renderer. The renderer uses the
	 * type to set the cell's icon and tool top text and the alias to display as its text.
	 */
	static class Entry
	{
		/** Key entry type */
		private static final int KEY = 0;

		/** Key pair entry type */
		private static final int KEY_PAIR = 1;

		/** Trusted certificate entry type */
		private static final int TRUSTED_CERTIFICATE = 2;

		/** Entry type */
		private final int m_iType;

		/** Entry alias */
		private final String m_sAlias;

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
		 * Get a trusted certificate entry.
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
			return m_iType == KEY;
		}

		/**
		 * Is entry of type key pair?
		 * 
		 * @return True if it is, false otherwise.
		 */
		public boolean isKeyPair()
		{
			return m_iType == KEY_PAIR;
		}

		/**
		 * Is entry of type trusted certificate?
		 * 
		 * @return True if it is, false otherwise.
		 */
		public boolean isTrustedCertificate()
		{
			return m_iType == TRUSTED_CERTIFICATE;
		}

		/**
		 * Returns the entry alias. Value displayed by renderer.
		 * 
		 * @return Entry alias
		 */
		@Override
		public String toString()
		{
			return m_sAlias;
		}
	}
}
