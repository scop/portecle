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

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableColumn;

/**
 * A dialog that displays the Java System Properties.
 */
public class DSystemProperties
    extends JDialog
{
	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/gui/about/resources");

	/**
	 * Creates new DSystemProperties dialog.
	 * 
	 * @param parent Parent window
	 * @param modal Is dialog modal?
	 */
	public DSystemProperties(JDialog parent, boolean modal)
	{
		super(parent, m_res.getString("DSystemProperties.Title"), (modal ? Dialog.DEFAULT_MODALITY_TYPE
		    : Dialog.ModalityType.MODELESS));
		initComponents();
	}

	/**
	 * Initialise the dialog's GUI components.
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
		jtSystemProperties.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

		// Add custom renderers for the table cells and headers
		int tWidth = 30; // arbitrary # of pixels for vertical scrollbar
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

		// Put the table into a scroll panew
		JScrollPane jspSystemPropertiesTable =
		    new JScrollPane(jtSystemProperties, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
		        JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		jspSystemPropertiesTable.getViewport().setBackground(jtSystemProperties.getBackground());

		// Put the scroll pane into a panel
		JPanel jpSystemPropertiesTable = new JPanel(new BorderLayout(10, 10));
		jpSystemPropertiesTable.setPreferredSize(new Dimension(tWidth, 300));
		jpSystemPropertiesTable.add(jspSystemPropertiesTable, BorderLayout.CENTER);
		jpSystemPropertiesTable.setBorder(new EmptyBorder(5, 5, 5, 5));

		final JButton jbOK = new JButton(m_res.getString("DSystemProperties.jbOK.text"));
		jbOK.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				okPressed();
			}
		});

		JPanel jpOK = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpOK.add(jbOK);

		getContentPane().add(jpSystemPropertiesTable, BorderLayout.CENTER);
		getContentPane().add(jpOK, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter()
		{
			@Override
			public void windowClosing(WindowEvent evt)
			{
				closeDialog();
			}
		});

		getRootPane().setDefaultButton(jbOK);

		pack();

		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				jbOK.requestFocus();
			}
		});
	}

	/**
	 * OK button pressed or otherwise activated.
	 */
	private void okPressed()
	{
		closeDialog();
	}

	/**
	 * Close the dialog.
	 */
	private void closeDialog()
	{
		setVisible(false);
		dispose();
	}
}
