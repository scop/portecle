/*
 * DSystemProperties.java
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

package net.sf.portecle.gui.about;

import static net.sf.portecle.FPortecle.RB;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableColumn;

import net.sf.portecle.PortecleJDialog;

/**
 * Modal dialog that displays the Java System Properties.
 */
/* package private */class DSystemProperties
    extends PortecleJDialog
{
	/**
	 * Creates new DSystemProperties dialog.
	 * 
	 * @param parent Parent window
	 */
	public DSystemProperties(JDialog parent)
	{
		super(parent, RB.getString("DSystemProperties.Title"), true);
		initComponents();
	}

	/**
	 * Initialize the dialog's GUI components.
	 */
	private void initComponents()
	{
		// System Properties table

		// Create the table using the appropriate table model
		SystemPropertiesTableModel spModel = new SystemPropertiesTableModel();
		spModel.load();

		JTable jtSystemProperties = new JTable(spModel);

		jtSystemProperties.setRowMargin(0);
		jtSystemProperties.getColumnModel().setColumnMargin(0);
		jtSystemProperties.getTableHeader().setReorderingAllowed(false);
		jtSystemProperties.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		// Add custom renderers for the table cells and headers
		int tWidth = 30; // arbitrary # of pixels for vertical scroll bar
		for (int iCnt = 0; iCnt < jtSystemProperties.getColumnCount(); iCnt++)
		{
			TableColumn column = jtSystemProperties.getColumnModel().getColumn(iCnt);

			if (iCnt == 0)
			{
				int w = 210;
				column.setPreferredWidth(w); // Property Name
				tWidth += w;
			}
			else
			{
				int w = 320;
				column.setPreferredWidth(w); // Property Value
				tWidth += w;
			}

			column.setHeaderRenderer(new SystemPropertiesTableHeadRend());
			column.setCellRenderer(new SystemPropertiesTableCellRend());
		}

		// Make the table sortable
		jtSystemProperties.setAutoCreateRowSorter(true);
		// ...and sort it by property name by default
		jtSystemProperties.getRowSorter().toggleSortOrder(0);

		// Put the table into a scroll pane
		JScrollPane jspSystemPropertiesTable = new JScrollPane(jtSystemProperties,
		    ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		jspSystemPropertiesTable.getViewport().setBackground(jtSystemProperties.getBackground());

		// Put the scroll pane into a panel
		JPanel jpSystemPropertiesTable = new JPanel(new BorderLayout(10, 10));
		jpSystemPropertiesTable.setPreferredSize(new Dimension(tWidth, 300));
		jpSystemPropertiesTable.add(jspSystemPropertiesTable, BorderLayout.CENTER);
		jpSystemPropertiesTable.setBorder(new EmptyBorder(5, 5, 5, 5));

		JButton jbOK = getOkButton(true);

		JPanel jpOK = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpOK.add(jbOK);

		getContentPane().add(jpSystemPropertiesTable, BorderLayout.CENTER);
		getContentPane().add(jpOK, BorderLayout.SOUTH);

		getRootPane().setDefaultButton(jbOK);

		initDialog();

		jbOK.requestFocusInWindow();
	}
}
