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

import static net.sf.portecle.FPortecle.RB;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Window;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.StringTokenizer;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableColumn;

import net.sf.portecle.PortecleJDialog;

/**
 * Modal dialog that displays information about the JAR files on the class path.
 */
public class DJarInfo
    extends PortecleJDialog
{
	/**
	 * Creates new DJarInfo dialog.
	 * 
	 * @param parent Parent window
	 * @throws IOException Problem occurred getting JAR information
	 */
	public DJarInfo(Window parent)
	    throws IOException
	{
		super(parent, RB.getString("DJarInfo.Title"), true);
		initComponents();
	}

	/**
	 * Initialize the dialog's GUI components.
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
		jtJarInfo.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		// Add custom renderers for the table cells and headers
		for (int iCnt = 0; iCnt < jtJarInfo.getColumnCount(); iCnt++)
		{
			TableColumn column = jtJarInfo.getColumnModel().getColumn(iCnt);

			column.setPreferredWidth(150);

			column.setHeaderRenderer(new JarInfoTableHeadRend());
			column.setCellRenderer(new JarInfoTableCellRend());
		}

		// Make the table sortable
		jtJarInfo.setAutoCreateRowSorter(true);
		// ...and sort it by jar file by default
		jtJarInfo.getRowSorter().toggleSortOrder(0);

		// Put the table into a scroll pane
		JScrollPane jspJarInfoTable = new JScrollPane(jtJarInfo, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
		    ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		jspJarInfoTable.getViewport().setBackground(jtJarInfo.getBackground());

		// Put the scroll pane into a panel
		JPanel jpJarInfoTable = new JPanel(new BorderLayout(10, 10));
		jpJarInfoTable.setPreferredSize(new Dimension(500, 150));
		jpJarInfoTable.add(jspJarInfoTable, BorderLayout.CENTER);
		jpJarInfoTable.setBorder(new EmptyBorder(5, 5, 5, 5));

		JButton jbOK = getOkButton(true);
		JPanel jpOK = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpOK.add(jbOK);

		getContentPane().add(jpJarInfoTable, BorderLayout.CENTER);
		getContentPane().add(jpOK, BorderLayout.SOUTH);

		getRootPane().setDefaultButton(jbOK);

		initDialog();

		jbOK.requestFocusInWindow();
	}

	/**
	 * Get JARs on class path.
	 * 
	 * @return JARs on class path
	 * @throws IOException Problem occurred getting JARs
	 */
	private JarFile[] getClassPathJars()
	    throws IOException
	{
		// Store JARs
		ArrayList<JarFile> vJars = new ArrayList<>();

		// Split class path into it's components using the path separator
		String sClassPath = System.getProperty("java.class.path");
		String sPathSeparator = System.getProperty("path.separator");

		StringTokenizer strTok = new StringTokenizer(sClassPath, sPathSeparator);

		// Store each JAR found on class path
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
		 * If only one JAR was found assume that application was started using "jar" option - look in JAR manifest's
		 * Class-Path entry for the rest of the JARs
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
					// Split "JAR class path" using spaces
					strTok = new StringTokenizer(sJarClassPath, " ");

					// Store each JAR found on "JAR class path"
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
}
