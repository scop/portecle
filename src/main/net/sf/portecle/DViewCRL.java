/*
 * DViewCRL.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2008 Ville Skyttä, ville.skytta@iki.fi
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
import java.awt.Color;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.text.DateFormat;
import java.text.MessageFormat;
import java.util.Collections;
import java.util.Date;
import java.util.ResourceBundle;
import java.util.Set;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import net.sf.portecle.gui.SwingHelper;

/**
 * Displays the details of a Certificate Revocation List (CRL).
 */
class DViewCRL
    extends JDialog
{
	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

	/** CRL Version text field */
	private JTextField m_jtfVersion;

	/** CRL Issuer text field */
	private JTextField m_jtfIssuer;

	/** CRL EffectiveDate text field */
	private JTextField m_jtfEffectiveDate;

	/** CRL Next Update text field */
	private JTextField m_jtfNextUpdate;

	/** CRL Signature Algorithm text field */
	private JTextField m_jtfSignatureAlgorithm;

	/** Button used to display the CRL's extensions */
	private JButton m_jbCrlExtensions;

	/** Revoked Certificates table */
	private JTable m_jtRevokedCerts;

	/** Button used to display the CRL's entries' extensions */
	private JButton m_jbCrlEntryExtensions;

	/** Stores CRL to display */
	private X509CRL m_crl;

	/**
	 * Creates new DViewCRL dialog.
	 * 
	 * @param parent Parent window
	 * @param sTitle The dialog title
	 * @param modal Is dialog modal?
	 * @param crl CRL to display
	 */
	public DViewCRL(Window parent, String sTitle, boolean modal, X509CRL crl)
	{
		super(parent, sTitle, (modal ? Dialog.DEFAULT_MODALITY_TYPE : Dialog.ModalityType.MODELESS));
		m_crl = crl;
		initComponents();
	}

	/**
	 * Initialise the dialog's GUI components.
	 */
	private void initComponents()
	{
		// CRL Details:

		// Grid Bag Constraints templates for labels and text fields
		// of CRL details
		GridBagConstraints gbcLbl = new GridBagConstraints();
		gbcLbl.gridx = 0;
		gbcLbl.gridwidth = 1;
		gbcLbl.gridheight = 1;
		gbcLbl.insets = new Insets(5, 5, 5, 5);
		gbcLbl.anchor = GridBagConstraints.EAST;

		GridBagConstraints gbcTf = new GridBagConstraints();
		gbcTf.gridx = 1;
		gbcTf.gridwidth = 1;
		gbcTf.gridheight = 1;
		gbcTf.insets = new Insets(5, 5, 5, 5);
		gbcTf.anchor = GridBagConstraints.WEST;

		// Version
		JLabel jlVersion = new JLabel(m_res.getString("DViewCRL.jlVersion.text"));
		GridBagConstraints gbc_jlVersion = (GridBagConstraints) gbcLbl.clone();
		gbc_jlVersion.gridy = 0;

		m_jtfVersion = new JTextField(3);
		m_jtfVersion.setEditable(false);
		m_jtfVersion.setToolTipText(m_res.getString("DViewCRL.m_jtfVersion.tooltip"));
		GridBagConstraints gbc_jtfVersion = (GridBagConstraints) gbcTf.clone();
		gbc_jtfVersion.gridy = 0;

		// Issuer
		JLabel jlIssuer = new JLabel(m_res.getString("DViewCRL.jlIssuer.text"));
		GridBagConstraints gbc_jlIssuer = (GridBagConstraints) gbcLbl.clone();
		gbc_jlIssuer.gridy = 1;

		m_jtfIssuer = new JTextField(40);
		m_jtfIssuer.setEditable(false);
		m_jtfIssuer.setToolTipText(m_res.getString("DViewCRL.m_jtfIssuer.tooltip"));
		GridBagConstraints gbc_jtfIssuer = (GridBagConstraints) gbcTf.clone();
		gbc_jtfIssuer.gridy = 1;

		// Effective Date
		JLabel jlEffectiveDate = new JLabel(m_res.getString("DViewCRL.jlEffectiveDate.text"));
		GridBagConstraints gbc_jlEffectiveDate = (GridBagConstraints) gbcLbl.clone();
		gbc_jlEffectiveDate.gridy = 2;

		m_jtfEffectiveDate = new JTextField(30);
		m_jtfEffectiveDate.setEditable(false);
		m_jtfEffectiveDate.setToolTipText(m_res.getString("DViewCRL.m_jtfEffectiveDate.tooltip"));
		GridBagConstraints gbc_jtfEffectiveDate = (GridBagConstraints) gbcTf.clone();
		gbc_jtfEffectiveDate.gridy = 2;

		// Next Update
		JLabel jlNextUpdate = new JLabel(m_res.getString("DViewCRL.jlNextUpdate.text"));
		GridBagConstraints gbc_jlNextUpdate = (GridBagConstraints) gbcLbl.clone();
		gbc_jlNextUpdate.gridy = 3;

		m_jtfNextUpdate = new JTextField(30);
		m_jtfNextUpdate.setEditable(false);
		m_jtfNextUpdate.setToolTipText(m_res.getString("DViewCRL.m_jtfNextUpdate.tooltip"));
		GridBagConstraints gbc_jtfNextUpdate = (GridBagConstraints) gbcTf.clone();
		gbc_jtfNextUpdate.gridy = 3;

		// Signature Algorithm
		JLabel jlSignatureAlgorithm = new JLabel(m_res.getString("DViewCRL.jlSignatureAlgorithm.text"));
		GridBagConstraints gbc_jlSignatureAlgorithm = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSignatureAlgorithm.gridy = 4;

		m_jtfSignatureAlgorithm = new JTextField(15);
		m_jtfSignatureAlgorithm.setEditable(false);
		m_jtfSignatureAlgorithm.setToolTipText(m_res.getString("DViewCRL.m_jtfSignatureAlgorithm.tooltip"));
		GridBagConstraints gbc_jtfSignatureAlgorithm = (GridBagConstraints) gbcTf.clone();
		gbc_jtfSignatureAlgorithm.gridy = 4;

		// CRL Extensions
		m_jbCrlExtensions = new JButton(m_res.getString("DViewCRL.m_jbCrlExtensions.text"));

		m_jbCrlExtensions.setMnemonic(m_res.getString("DViewCRL.m_jbCrlExtensions.mnemonic").charAt(0));
		m_jbCrlExtensions.setToolTipText(m_res.getString("DViewCRL.m_jbCrlExtensions.tooltip"));
		m_jbCrlExtensions.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				crlExtensionsPressed();
			}
		});

		GridBagConstraints gbc_jbExtensions = new GridBagConstraints();
		gbc_jbExtensions.gridx = 0;
		gbc_jbExtensions.gridy = 5;
		gbc_jbExtensions.gridwidth = 2;
		gbc_jbExtensions.gridheight = 1;
		gbc_jbExtensions.insets = new Insets(5, 5, 5, 5);
		gbc_jbExtensions.anchor = GridBagConstraints.EAST;

		// Revoked certificates table

		// Create the table using the appropriate table model
		RevokedCertsTableModel rcModel = new RevokedCertsTableModel();

		m_jtRevokedCerts = new JTable(rcModel);

		m_jtRevokedCerts.setShowGrid(false);
		m_jtRevokedCerts.setRowMargin(0);
		m_jtRevokedCerts.getColumnModel().setColumnMargin(0);
		m_jtRevokedCerts.getTableHeader().setReorderingAllowed(false);
		m_jtRevokedCerts.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);

		// Add custom renderers for the table cells and headers
		for (int iCnt = 0; iCnt < m_jtRevokedCerts.getColumnCount(); iCnt++)
		{
			TableColumn column = m_jtRevokedCerts.getColumnModel().getColumn(iCnt);

			if (iCnt == 0)
			{
				column.setPreferredWidth(150);
			}

			column.setHeaderRenderer(new RevokedCertsTableHeadRend());
			column.setCellRenderer(new RevokedCertsTableCellRend());
		}

		ListSelectionModel listSelectionModel = m_jtRevokedCerts.getSelectionModel();
		listSelectionModel.addListSelectionListener(new ListSelectionListener()
		{
			public void valueChanged(ListSelectionEvent evt)
			{
				// Ignore spurious events
				if (!evt.getValueIsAdjusting())
				{
					crlEntrySelection();
				}
			}
		});

		// Make the table sortable
		TableRowSorter<RevokedCertsTableModel> sorter = new TableRowSorter<RevokedCertsTableModel>(rcModel);
		m_jtRevokedCerts.setRowSorter(sorter);
		// ...and sort it by serial number by default
		sorter.toggleSortOrder(0);

		// Put the table into a scroll pane
		JScrollPane jspRevokedCertsTable =
		    new JScrollPane(m_jtRevokedCerts, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
		        JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		jspRevokedCertsTable.getViewport().setBackground(m_jtRevokedCerts.getBackground());

		// Put the scroll pane into a panel
		JPanel jpRevokedCertsTable = new JPanel(new BorderLayout(10, 10));
		// More for the benefit of a reduced height
		jpRevokedCertsTable.setPreferredSize(new Dimension(100, 200));
		jpRevokedCertsTable.add(jspRevokedCertsTable, BorderLayout.CENTER);

		// CRL Entry Extensions
		m_jbCrlEntryExtensions = new JButton(m_res.getString("DViewCRL.m_jbCrlEntryExtensions.text"));

		m_jbCrlEntryExtensions.setMnemonic(m_res.getString("DViewCRL.m_jbCrlEntryExtensions.mnemonic").charAt(
		    0));
		m_jbCrlEntryExtensions.setToolTipText(m_res.getString("DViewCRL.m_jbCrlEntryExtensions.tooltip"));
		m_jbCrlEntryExtensions.setEnabled(false);
		m_jbCrlEntryExtensions.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				crlEntryExtensionsPressed();
			}
		});

		JPanel jpCrlEntryExtensions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		jpCrlEntryExtensions.add(m_jbCrlEntryExtensions);

		jpRevokedCertsTable.add(jpCrlEntryExtensions, BorderLayout.SOUTH);

		GridBagConstraints gbc_jpRevokedCertsTable = new GridBagConstraints();
		gbc_jpRevokedCertsTable.gridx = 0;
		gbc_jpRevokedCertsTable.gridy = 6;
		gbc_jpRevokedCertsTable.gridwidth = 2;
		gbc_jpRevokedCertsTable.gridheight = 1;
		gbc_jpRevokedCertsTable.insets = new Insets(5, 5, 5, 5);
		gbc_jpRevokedCertsTable.fill = GridBagConstraints.BOTH;
		gbc_jpRevokedCertsTable.anchor = GridBagConstraints.CENTER;

		JPanel jpCRL = new JPanel(new GridBagLayout());
		jpCRL.setBorder(new CompoundBorder(new EmptyBorder(10, 10, 10, 10), new EtchedBorder()));

		// Put it all together
		jpCRL.add(jlVersion, gbc_jlVersion);
		jpCRL.add(m_jtfVersion, gbc_jtfVersion);
		jpCRL.add(jlIssuer, gbc_jlIssuer);
		jpCRL.add(m_jtfIssuer, gbc_jtfIssuer);
		jpCRL.add(jlEffectiveDate, gbc_jlEffectiveDate);
		jpCRL.add(m_jtfEffectiveDate, gbc_jtfEffectiveDate);
		jpCRL.add(jlNextUpdate, gbc_jlNextUpdate);
		jpCRL.add(m_jtfNextUpdate, gbc_jtfNextUpdate);
		jpCRL.add(jlSignatureAlgorithm, gbc_jlSignatureAlgorithm);
		jpCRL.add(m_jtfSignatureAlgorithm, gbc_jtfSignatureAlgorithm);
		jpCRL.add(m_jbCrlExtensions, gbc_jbExtensions);
		jpCRL.add(jpRevokedCertsTable, gbc_jpRevokedCertsTable);

		// Populate the dialog with the CRL
		populateDialog();

		// Add border with number of entries in CRL
		jpRevokedCertsTable.setBorder(new CompoundBorder(new TitledBorder(new EtchedBorder(),
		    MessageFormat.format(m_res.getString("DViewCRL.TableTitle"), m_jtRevokedCerts.getRowCount())),
		    new EmptyBorder(5, 5, 5, 5)));

		// OK button
		JPanel jpOK = new JPanel(new FlowLayout(FlowLayout.CENTER));

		final JButton jbOK = new JButton(m_res.getString("DViewCRL.jbOK.text"));
		jbOK.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				okPressed();
			}
		});

		jpOK.add(jbOK);

		// Put it all together
		getContentPane().add(jpCRL, BorderLayout.CENTER);
		getContentPane().add(jpOK, BorderLayout.SOUTH);

		setResizable(false);

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
	 * Populate the dialog with the CRL's details.
	 */
	private void populateDialog()
	{
		// Populate CRL fields:

		// Has the CRL [been issued/been updated]
		Date currentDate = new Date();

		Date effectiveDate = m_crl.getThisUpdate();
		Date updateDate = m_crl.getNextUpdate();

		boolean bEffective = currentDate.before(effectiveDate);
		boolean bUpdateAvailable = currentDate.after(updateDate);

		// Version
		m_jtfVersion.setText(Integer.toString(m_crl.getVersion()));
		m_jtfVersion.setCaretPosition(0);

		// Issuer
		m_jtfIssuer.setText(m_crl.getIssuerDN().toString());
		m_jtfIssuer.setCaretPosition(0);

		// Effective Date (include timezone)
		m_jtfEffectiveDate.setText(DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.LONG).format(
		    effectiveDate));

		if (bEffective)
		{
			m_jtfEffectiveDate.setText(MessageFormat.format(
			    m_res.getString("DViewCRL.m_jtfEffectiveDate.noteffective.text"),
			    m_jtfEffectiveDate.getText()));
			m_jtfEffectiveDate.setForeground(Color.red);
		}
		else
		{
			m_jtfEffectiveDate.setForeground(m_jtfVersion.getForeground());
		}
		m_jtfEffectiveDate.setCaretPosition(0);

		// Next Update (include timezone)
		m_jtfNextUpdate.setText(DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.LONG).format(
		    updateDate));

		if (bUpdateAvailable)
		{
			m_jtfNextUpdate.setText(MessageFormat.format(
			    m_res.getString("DViewCRL.m_jtfNextUpdate.updateavailable.text"), m_jtfNextUpdate.getText()));
			m_jtfNextUpdate.setForeground(Color.red);
		}
		else
		{
			m_jtfNextUpdate.setForeground(m_jtfVersion.getForeground());
		}
		m_jtfNextUpdate.setCaretPosition(0);

		// Signature Algorithm
		m_jtfSignatureAlgorithm.setText(m_crl.getSigAlgName());
		m_jtfSignatureAlgorithm.setCaretPosition(0);

		// Enable/disable extensions button
		Set<String> critExts = m_crl.getCriticalExtensionOIDs();
		Set<String> nonCritExts = m_crl.getNonCriticalExtensionOIDs();

		if ((critExts != null && critExts.size() != 0) || (nonCritExts != null && nonCritExts.size() != 0))
		{
			// Extensions
			m_jbCrlExtensions.setEnabled(true);
		}
		else
		{
			// No extensions
			m_jbCrlExtensions.setEnabled(false);
		}

		// Populate Revoked Certificates table
		Set<? extends X509CRLEntry> revokedCertsSet = m_crl.getRevokedCertificates();
		if (revokedCertsSet == null)
		{
			revokedCertsSet = Collections.emptySet();
		}

		X509CRLEntry[] revokedCerts = revokedCertsSet.toArray(new X509CRLEntry[revokedCertsSet.size()]);
		RevokedCertsTableModel revokedCertsTableModel = (RevokedCertsTableModel) m_jtRevokedCerts.getModel();
		revokedCertsTableModel.load(revokedCerts);

		// Select first CRL
		if (revokedCertsTableModel.getRowCount() > 0)
		{
			m_jtRevokedCerts.changeSelection(0, 0, false, false);
		}
	}

	/**
	 * CRL entry selected or deselected. Enable/disable the "CRL Extensions" button accordingly (ie. enable if
	 * if only one extension is selected and it has extensions.
	 */
	private void crlEntrySelection()
	{
		ListSelectionModel listSelectionModel = m_jtRevokedCerts.getSelectionModel();

		if (!listSelectionModel.isSelectionEmpty()) // Enry must be selected
		{
			// Only one entry though
			if (listSelectionModel.getMinSelectionIndex() == listSelectionModel.getMaxSelectionIndex())
			{
				// Get serial number of entry
				int iRow = listSelectionModel.getMinSelectionIndex();
				BigInteger serialNumber = (BigInteger) m_jtRevokedCerts.getValueAt(iRow, 0);

				// Find CRL entry using serial number
				Set<? extends X509CRLEntry> revokedCertsSet = m_crl.getRevokedCertificates();
				X509CRLEntry x509CrlEntry = null;
				for (X509CRLEntry entry : revokedCertsSet)
				{
					if (serialNumber.equals(entry.getSerialNumber()))
					{
						x509CrlEntry = entry;
						break;
					}
				}

				if (x509CrlEntry != null && x509CrlEntry.hasExtensions())
				{
					m_jbCrlEntryExtensions.setEnabled(true);
					return;
				}
			}
		}

		// Disable "CRL Extensions" button
		m_jbCrlEntryExtensions.setEnabled(false);
	}

	/**
	 * CRL extensions button pressed or otherwise activated. Show the extensions of the CRL.
	 */
	private void crlExtensionsPressed()
	{
		DViewExtensions dViewExtensions =
		    new DViewExtensions(this, m_res.getString("DViewCRL.Extensions.Title"), true, m_crl);
		dViewExtensions.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dViewExtensions);
	}

	/**
	 * CRL entry extensions button pressed or otherwise activated. Show the extensions of the selected CRL
	 * entry.
	 */
	private void crlEntryExtensionsPressed()
	{
		ListSelectionModel listSelectionModel = m_jtRevokedCerts.getSelectionModel();

		if (!listSelectionModel.isSelectionEmpty()) // Entry must be selected
		{
			// Only one entry though
			if (listSelectionModel.getMinSelectionIndex() == listSelectionModel.getMaxSelectionIndex())
			{
				// Get serial number of entry
				int iRow = listSelectionModel.getMinSelectionIndex();
				BigInteger serialNumber =
				    (BigInteger) ((RevokedCertsTableModel) m_jtRevokedCerts.getModel()).getValueAt(iRow, 0);

				// Find CRL entry using serial number
				Set<? extends X509CRLEntry> revokedCertsSet = m_crl.getRevokedCertificates();
				X509CRLEntry x509CrlEntry = null;
				for (X509CRLEntry entry : revokedCertsSet)
				{
					if (serialNumber.equals(entry.getSerialNumber()))
					{
						x509CrlEntry = entry;
						break;
					}
				}

				if (x509CrlEntry != null && x509CrlEntry.hasExtensions())
				{
					DViewExtensions dViewExtensions =
					    new DViewExtensions(this, m_res.getString("DViewCRL." + "EntryExtensions.Title"),
					        true, x509CrlEntry);
					dViewExtensions.setLocationRelativeTo(this);
					SwingHelper.showAndWait(dViewExtensions);
				}
			}
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
	 * Hides the View CRL dialog.
	 */
	private void closeDialog()
	{
		setVisible(false);
		dispose();
	}
}
