/*
 * DViewExtensions.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004 Ville Skyttä, ville.skytta@iki.fi
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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.cert.X509Extension;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableColumn;

import net.sf.portecle.crypto.CryptoException;
import net.sf.portecle.crypto.X509Ext;
import net.sf.portecle.gui.SwingHelper;
import net.sf.portecle.gui.error.DThrowable;

/**
 * Displays the details of X.509 Extensions.
 */
class DViewExtensions
    extends JDialog
{
	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

	/** Extensions table */
	private JTable m_jtExtensions;

	/** Extension value text area */
	private JTextArea m_jtaExtensionValue;

	/** Extensions to display */
	private X509Extension m_extensions;

	/**
	 * Creates new DViewExtensions dialog where the parent is a frame.
	 * 
	 * @param parent Parent frame
	 * @param sTitle The dialog title
	 * @param bModal Is dialog modal?
	 * @param extensions Extensions to display
	 * @throws CryptoException A problem was encountered getting the extension details
	 */
	public DViewExtensions(JFrame parent, String sTitle, boolean bModal, X509Extension extensions)
	{
		super(parent, sTitle, bModal);
		m_extensions = extensions;
		initComponents();
	}

	/**
	 * Creates new DViewExtensions dialog where the parent is a dialog.
	 * 
	 * @param parent Parent dialog
	 * @param sTitle The dialog title
	 * @param bModal Is dialog modal?
	 * @param extensions Extensions to display
	 */
	public DViewExtensions(JDialog parent, String sTitle, boolean bModal, X509Extension extensions)
	{
		super(parent, sTitle, bModal);
		m_extensions = extensions;
		initComponents();
	}

	/**
	 * Initialise the dialog's GUI components.
	 */
	private void initComponents()
	{
		// There must be extensions to display
		assert (m_extensions.getCriticalExtensionOIDs() != null && m_extensions.getCriticalExtensionOIDs().size() != 0) ||
		    (m_extensions.getNonCriticalExtensionOIDs() != null && m_extensions.getNonCriticalExtensionOIDs().size() != 0);

		// Extensions table

		// Create the table using the appropriate table model
		ExtensionsTableModel extensionsTableModel = new ExtensionsTableModel();
		m_jtExtensions = new JTable(extensionsTableModel);

		m_jtExtensions.setShowGrid(false);
		m_jtExtensions.setRowMargin(0);
		m_jtExtensions.getColumnModel().setColumnMargin(0);
		m_jtExtensions.getTableHeader().setReorderingAllowed(false);
		m_jtExtensions.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
		m_jtExtensions.setRowHeight(18);

		// Add custom renderers for the table cells and headers
		for (int iCnt = 0; iCnt < m_jtExtensions.getColumnCount(); iCnt++)
		{
			TableColumn column = m_jtExtensions.getColumnModel().getColumn(iCnt);
			column.setHeaderRenderer(new ExtensionsTableHeadRend());
			column.setCellRenderer(new ExtensionsTableCellRend());
		}

		/*
		 * Make the first column small and not resizable (it holds an icon to represent the criticality of an
		 * extension)
		 */
		TableColumn criticalCol = m_jtExtensions.getColumnModel().getColumn(0);
		criticalCol.setResizable(false);
		criticalCol.setMinWidth(20);
		criticalCol.setMaxWidth(20);
		criticalCol.setPreferredWidth(20);

		// If extension selected/deselected update extension value text area
		ListSelectionModel selectionModel = m_jtExtensions.getSelectionModel();
		selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		selectionModel.addListSelectionListener(new ListSelectionListener()
		{
			public void valueChanged(ListSelectionEvent evt)
			{
				if (!evt.getValueIsAdjusting())
				{
					updateExtensionValue();
				}
			}
		});

		// Put the table into a scroll pane
		JScrollPane jspExtensionsTable =
		    new JScrollPane(m_jtExtensions, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
		        JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		jspExtensionsTable.getViewport().setBackground(m_jtExtensions.getBackground());

		// Put the scroll pane into a panel
		JPanel jpExtensionsTable = new JPanel(new BorderLayout(10, 10));
		jpExtensionsTable.setPreferredSize(new Dimension(520, 200));
		jpExtensionsTable.add(jspExtensionsTable, BorderLayout.CENTER);

		// Panel to hold Extension Value controls
		JPanel jpExtensionValue = new JPanel(new BorderLayout(10, 10));

		// Extension Value label
		JLabel jlExtensionValue = new JLabel(m_res.getString("DViewExtensions.jlExtensionValue.text"));

		// Put label into panel
		jpExtensionValue.add(jlExtensionValue, BorderLayout.NORTH);

		// Extension Value text area
		m_jtaExtensionValue = new JTextArea();
		m_jtaExtensionValue.setFont(new Font("Monospaced", Font.PLAIN,
		    m_jtaExtensionValue.getFont().getSize()));
		m_jtaExtensionValue.setEditable(false);
		m_jtaExtensionValue.setToolTipText(m_res.getString("DViewExtensions.m_jtaExtensionValue.tooltip"));
		m_jtaExtensionValue.setTabSize(2);

		// Put the text area into a scroll pane
		JScrollPane jspExtensionValue =
		    new JScrollPane(m_jtaExtensionValue, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
		        JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

		// Put the scroll pane into a panel
		JPanel jpExtensionValueTextArea = new JPanel(new BorderLayout(10, 10));
		jpExtensionValueTextArea.setPreferredSize(new Dimension(520, 200));
		jpExtensionValueTextArea.add(jspExtensionValue, BorderLayout.CENTER);

		// Put text area panel into Extension Value controls panel
		jpExtensionValue.add(jpExtensionValueTextArea, BorderLayout.CENTER);

		// Put Extensions table and Extension Value text area together in
		// extensions panel
		JPanel jpExtensions = new JPanel(new GridLayout(2, 1, 5, 5));
		jpExtensions.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
		    new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jpExtensions.add(jpExtensionsTable);
		jpExtensions.add(jpExtensionValue);

		// OK button
		JPanel jpOK = new JPanel(new FlowLayout(FlowLayout.CENTER));

		final JButton jbOK = new JButton(m_res.getString("DViewExtensions.jbOK.text"));
		jbOK.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				okPressed();
			}
		});

		jpOK.add(jbOK);

		// Populate table with extensions
		extensionsTableModel.load(m_extensions);

		// Select first extension
		if (extensionsTableModel.getRowCount() > 0)
		{
			m_jtExtensions.changeSelection(0, 0, false, false);
		}

		// Put it all together
		getContentPane().add(jpExtensions, BorderLayout.CENTER);
		getContentPane().add(jpOK, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter()
		{
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
	 * Update the value of the Extension Value text area depending on whether or not an extension has been
	 * selected in the table.
	 */
	private void updateExtensionValue()
	{
		int iSelectedRow = m_jtExtensions.getSelectedRow();

		if (iSelectedRow == -1)
		{
			// No extension selected - clear text area
			m_jtaExtensionValue.setText("");
		}
		else
		{
			// Extension selected - get value for extension
			String sOid = m_jtExtensions.getModel().getValueAt(iSelectedRow, 2).toString();

			byte[] bValue = m_extensions.getExtensionValue(sOid);

			// Don't care about criticality
			X509Ext ext = new X509Ext(sOid, bValue, false);

			try
			{
				m_jtaExtensionValue.setText(ext.getStringValue());
			}
			// Don't like this but *anything* could go wrong in there
			catch (Exception ex)
			{
				m_jtaExtensionValue.setText("");
				DThrowable dThrowable = new DThrowable(this, true, ex);
				dThrowable.setLocationRelativeTo(this);
				SwingHelper.showAndWait(dThrowable);
			}
			m_jtaExtensionValue.setCaretPosition(0);
		}
	}

	/**
	 * OK button pressed or otherwise activated.
	 */
	private void okPressed()
	{
		closeDialog();
	}

	/**
	 * Hides the View Extensions dialog.
	 */
	private void closeDialog()
	{
		setVisible(false);
		dispose();
	}
}
