/*
 * DViewExtensions.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004-2008 Ville Skyttä, ville.skytta@iki.fi
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

import java.awt.BorderLayout;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.Window;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.cert.X509Extension;
import java.text.MessageFormat;

import javax.swing.JButton;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import javax.swing.text.AttributeSet;
import javax.swing.text.Element;
import javax.swing.text.html.HTML;

import net.sf.portecle.crypto.OidComparator;
import net.sf.portecle.crypto.X509Ext;
import net.sf.portecle.crypto.X509Ext.LinkClass;
import net.sf.portecle.gui.DesktopUtil;
import net.sf.portecle.gui.error.DThrowable;

/**
 * Displays the details of X.509 Extensions.
 */
class DViewExtensions
    extends PortecleJDialog
{
	/** Extensions table */
	private JTable m_jtExtensions;

	/** Extension value text area */
	private JEditorPane m_jtaExtensionValue;

	/** Extensions to display */
	private final X509Extension m_extensions;

	/**
	 * Creates new DViewExtensions dialog.
	 * 
	 * @param parent Parent window
	 * @param sTitle The dialog title
	 * @param modal Is dialog modal?
	 * @param extensions Extensions to display
	 */
	public DViewExtensions(Window parent, String sTitle, boolean modal, X509Extension extensions)
	{
		super(parent, sTitle, modal);
		m_extensions = extensions;
		initComponents();
	}

	/**
	 * Initialize the dialog's GUI components.
	 */
	private void initComponents()
	{
		// There must be extensions to display
		assert (m_extensions.getCriticalExtensionOIDs() != null &&
		    !m_extensions.getCriticalExtensionOIDs().isEmpty()) ||
		    (m_extensions.getNonCriticalExtensionOIDs() != null &&
		        !m_extensions.getNonCriticalExtensionOIDs().isEmpty());

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

		// Make the first column small and not resizable (it holds an icon to represent the criticality of an
		// extension)
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
			@Override
			public void valueChanged(ListSelectionEvent evt)
			{
				if (!evt.getValueIsAdjusting())
				{
					updateExtensionValue();
				}
			}
		});

		// Make the table sortable
		TableRowSorter<ExtensionsTableModel> sorter = new TableRowSorter<>(extensionsTableModel);
		sorter.setComparator(2, new OidComparator());
		m_jtExtensions.setRowSorter(sorter);
		// ...and sort it by extension name by default
		sorter.toggleSortOrder(1);

		// Put the table into a scroll pane
		JScrollPane jspExtensionsTable = new JScrollPane(m_jtExtensions,
		    ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		jspExtensionsTable.getViewport().setBackground(m_jtExtensions.getBackground());

		// Put the scroll pane into a panel
		JPanel jpExtensionsTable = new JPanel(new BorderLayout(10, 10));
		jpExtensionsTable.setPreferredSize(new Dimension(520, 200));
		jpExtensionsTable.add(jspExtensionsTable, BorderLayout.CENTER);

		// Panel to hold Extension Value controls
		JPanel jpExtensionValue = new JPanel(new BorderLayout(10, 10));

		// Extension Value label
		JLabel jlExtensionValue = new JLabel(RB.getString("DViewExtensions.jlExtensionValue.text"));

		// Put label into panel
		jpExtensionValue.add(jlExtensionValue, BorderLayout.NORTH);

		// Extension value area

		m_jtaExtensionValue = new JEditorPane("text/html", "");
		m_jtaExtensionValue.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, true);
		m_jtaExtensionValue.setFont(m_jtExtensions.getFont());
		m_jtaExtensionValue.setEditable(false);
		m_jtaExtensionValue.setToolTipText(RB.getString("DViewExtensions.m_jtaExtensionValue.tooltip"));
		jlExtensionValue.setLabelFor(m_jtaExtensionValue);

		final JEditorPane editorPane = m_jtaExtensionValue;

		m_jtaExtensionValue.addHyperlinkListener(new HyperlinkListener()
		{
			@Override
			public void hyperlinkUpdate(HyperlinkEvent evt)
			{
				if (evt.getEventType() == HyperlinkEvent.EventType.ACTIVATED)
				{
					LinkClass linkClass = LinkClass.BROWSER;
					URL url = evt.getURL();

					Element el = evt.getSourceElement();
					AttributeSet attrs = el.getAttributes();
					if (attrs != null)
					{
						attrs = (AttributeSet) attrs.getAttribute(HTML.Tag.A);
						if (attrs != null)
						{
							try
							{
								linkClass = LinkClass.valueOf((String) attrs.getAttribute(HTML.Attribute.CLASS));
							}
							catch (RuntimeException e)
							{
								// Ignored
							}

							if (url == null)
							{
								// Can happen e.g. for ldap:// URLs
								Object href = attrs.getAttribute(HTML.Attribute.HREF);
								if (href instanceof CharSequence)
								{
									try
									{
										url = new URL(href.toString());
									}
									catch (MalformedURLException e)
									{
										DThrowable.showAndWait(DViewExtensions.this, null, e);
									}
								}
							}
						}
					}

					if (url == null)
					{
						return;
					}

					boolean tryBrowser = false;

					try
					{
						editorPane.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));

						switch (linkClass)
						{
							case CRL:

								// View in CRL viewer dialog
								if (!DViewCRL.showAndWait(DViewExtensions.this, url))
								{
									// Ask to view in a browser if it failed
									int iSelected = JOptionPane.showConfirmDialog(DViewExtensions.this,
		                                RB.getString("FPortecle.CrlViewFailed.message"),
		                                MessageFormat.format(RB.getString("FPortecle.CrlDetails.Title"), url),
		                                JOptionPane.YES_NO_OPTION);
									if (iSelected == JOptionPane.YES_OPTION)
									{
										tryBrowser = true;
									}
								}
								break;

							case CERTIFICATE:

								// View in certificate viewer dialog
								if (!DViewCertificate.showAndWait(DViewExtensions.this, url))
								{
									// Ask to view in a browser if it failed
									int iSelected = JOptionPane.showConfirmDialog(DViewExtensions.this,
		                                RB.getString("FPortecle.CertViewFailed.message"),
		                                MessageFormat.format(RB.getString("FPortecle.CertDetails.Title"), url),
		                                JOptionPane.YES_NO_OPTION);
									if (iSelected == JOptionPane.YES_OPTION)
									{
										tryBrowser = true;
									}
								}
								break;

							case OCSP:
								// TODO: check it
							default:
								tryBrowser = true;
						}

						if (tryBrowser)
						{
							try
							{
								DesktopUtil.browse(DViewExtensions.this, evt.getURL().toURI());
							}
							catch (URISyntaxException e)
							{
								DThrowable.showAndWait(DViewExtensions.this, null, e);
							}
						}

					}
					finally
					{
						editorPane.setCursor(Cursor.getDefaultCursor());
					}
				}
			}
		});

		// Put the text area into a scroll pane
		JScrollPane jspExtensionValue = new JScrollPane(m_jtaExtensionValue,
		    ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

		// Put the scroll pane into a panel
		JPanel jpExtensionValueTextArea = new JPanel(new BorderLayout(10, 10));
		jpExtensionValueTextArea.setPreferredSize(new Dimension(520, 200));
		jpExtensionValueTextArea.add(jspExtensionValue, BorderLayout.CENTER);

		// Put text area panel into Extension Value controls panel
		jpExtensionValue.add(jpExtensionValueTextArea, BorderLayout.CENTER);

		// Put Extensions table and Extension Value text area together in extensions panel
		JPanel jpExtensions = new JPanel(new GridLayout(2, 1, 5, 5));
		jpExtensions.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5),
		    new CompoundBorder(new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jpExtensions.add(jpExtensionsTable);
		jpExtensions.add(jpExtensionValue);

		// OK button
		JPanel jpOK = new JPanel(new FlowLayout(FlowLayout.CENTER));
		final JButton jbOK = getOkButton(true);
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

		getRootPane().setDefaultButton(jbOK);

		initDialog();

		jbOK.requestFocusInWindow();
	}

	/**
	 * Update the value of the Extension Value text area depending on whether or not an extension has been selected in
	 * the table.
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
			String sOid = m_jtExtensions.getValueAt(iSelectedRow, 2).toString();

			byte[] bValue = m_extensions.getExtensionValue(sOid);

			// Don't care about criticality
			X509Ext ext = new X509Ext(sOid, bValue, false);

			final String HEADER = "<html><head><style type=\"text/css\">ul { list-style-type: none; margin: 0; }\n" +
			    "li ul { margin-left: 10px; }\n</style></head><body>";
			final String FOOTER = "</body></html>";

			try
			{
				m_jtaExtensionValue.setText(HEADER + ext.getStringValue() + FOOTER);
			}
			// Don't like this but *anything* could go wrong in there
			catch (Exception ex)
			{
				m_jtaExtensionValue.setText("");
				DThrowable.showAndWait(this, null, ex);
			}
			m_jtaExtensionValue.setCaretPosition(0);
		}
	}
}
