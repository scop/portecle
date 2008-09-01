/*
 * DJarInfo.java
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

package net.sf.portecle.gui.jar;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.ResourceBundle;
import java.util.StringTokenizer;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

/**
 * A dialog that displays information about the JAR files on the classpath.
 */
public class DJarInfo
    extends JDialog
{
	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/gui/jar/resources");

	/**
	 * Creates new DJarInfo dialog.
	 * 
	 * @param parent Parent window
	 * @param modal Is dialog modal?
	 * @throws IOException Problem occurred getting JAR information
	 */
	public DJarInfo(Window parent, boolean modal)
	    throws IOException
	{
		super(parent, m_res.getString("DJarInfo.Title"), (modal ? Dialog.DEFAULT_MODALITY_TYPE
		    : Dialog.ModalityType.MODELESS));
		initComponents();
	}

	/**
	 * Initialise the dialog's GUI components.
	 * 
	 * @throws IOException Problem occurred getting JAR information
	 */
	private void initComponents()
	    throws IOException
	{
		JarFile[] jarFiles = getClassPathJars();

		// JAR Information table

		// Create the table using the appropriate table model
		JarInfoTableModel jiModel = new JarInfoTableModel();
		jiModel.load(jarFiles);

		JTable jtJarInfo = new JTable(jiModel);

		jtJarInfo.setRowMargin(0);
		jtJarInfo.getColumnModel().setColumnMargin(0);
		jtJarInfo.getTableHeader().setReorderingAllowed(false);
		jtJarInfo.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

		// Add custom renderers for the table cells and headers
		for (int iCnt = 0; iCnt < jtJarInfo.getColumnCount(); iCnt++)
		{
			TableColumn column = jtJarInfo.getColumnModel().getColumn(iCnt);

			column.setPreferredWidth(150);

			column.setHeaderRenderer(new JarInfoTableHeadRend());
			column.setCellRenderer(new JarInfoTableCellRend());
		}

		// Make the table sortable
		TableRowSorter<JarInfoTableModel> sorter = new TableRowSorter<JarInfoTableModel>(jiModel);
		jtJarInfo.setRowSorter(sorter);
		// ...and sort it by jar file by default
		sorter.toggleSortOrder(0);

		// Put the table into a scroll pane
		JScrollPane jspJarInfoTable =
		    new JScrollPane(jtJarInfo, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
		        JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		jspJarInfoTable.getViewport().setBackground(jtJarInfo.getBackground());

		// Put the scroll pane into a panel
		JPanel jpJarInfoTable = new JPanel(new BorderLayout(10, 10));
		jpJarInfoTable.setPreferredSize(new Dimension(500, 150));
		jpJarInfoTable.add(jspJarInfoTable, BorderLayout.CENTER);
		jpJarInfoTable.setBorder(new EmptyBorder(5, 5, 5, 5));

		final JButton jbOK = new JButton(m_res.getString("DJarInfo.jbOK.text"));
		jbOK.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				okPressed();
			}
		});

		JPanel jpOK = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpOK.add(jbOK);

		getContentPane().add(jpJarInfoTable, BorderLayout.CENTER);
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
	 * Get JARs on classpath.
	 * 
	 * @return JARs on classpath
	 * @throws IOException Problem occurred getting JARs
	 */
	private JarFile[] getClassPathJars()
	    throws IOException
	{
		// Store JARs
		ArrayList<JarFile> vJars = new ArrayList<JarFile>();

		// Split classpath into it's components using the path separator
		String sClassPath = System.getProperty("java.class.path");
		String sPathSeparator = System.getProperty("path.separator");

		StringTokenizer strTok = new StringTokenizer(sClassPath, sPathSeparator);

		// Store each JAR found on classpath
		while (strTok.hasMoreTokens())
		{
			String sClassPathEntry = strTok.nextToken();

			File file = new File(sClassPathEntry);

			if (isJarFile(file))
			{
				vJars.add(new JarFile(file));
			}
		}

		/*
		 * If only one JAR was found assume that application was started using "jar" option - look in JAR
		 * manifest's Class-Path entry for the rest of the JARs
		 */
		if (vJars.size() == 1)
		{
			// Get manifest
			JarFile jarFile = vJars.get(0);
			Manifest manifest = jarFile.getManifest();

			if (manifest != null) // Manifest may not exist
			{
				// Get Class-Path entry
				Attributes attributes = manifest.getMainAttributes();
				String sJarClassPath = attributes.getValue("Class-Path");

				if (sJarClassPath != null)
				{
					// Split "JAR classpath" using spaces
					strTok = new StringTokenizer(sJarClassPath, " ");

					// Store each JAR found on "JAR classpath"
					while (strTok.hasMoreTokens())
					{
						String sJarClassPathEntry = strTok.nextToken();

						File file = new File(new File(jarFile.getName()).getParent(), sJarClassPathEntry);

						if (isJarFile(file))
						{
							vJars.add(new JarFile(file));
						}
					}
				}
			}
		}

		// Return JARs in an array
		return vJars.toArray(new JarFile[vJars.size()]);
	}

	/**
	 * Is supplied file a JAR file? That is, is it a regular file that it has an extension of "ZIP" or "JAR".
	 * 
	 * @param file The file
	 * @return True if it is, false otherwise
	 */
	private boolean isJarFile(File file)
	{
		if (file.isFile())
		{
			String sName = file.getName().toLowerCase();

			if (sName.endsWith(".jar") || sName.endsWith(".zip"))
			{
				return true;
			}
		}

		return false;
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
