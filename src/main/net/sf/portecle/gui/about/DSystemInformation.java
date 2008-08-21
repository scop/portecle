/*
 * DSystemInformation.java
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
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.text.MessageFormat;
import java.util.Locale;
import java.util.Properties;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import net.sf.portecle.gui.SwingHelper;

/**
 * A dialog which displays general system information: OS, Locale, Java version, Java vendor, Java vendor URL,
 * JVM total memory and JVM free memory.
 */
public class DSystemInformation
    extends JDialog
{
	/** Width of system information text fields */
	private static final int VALUE_WIDTH = 25;

	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/gui/about/resources");

	/**
	 * Creates new DSystemInformation dialog where the parent is a dialog.
	 * 
	 * @param parent Parent dialog
	 * @param bModal Is dialog modal?
	 */
	public DSystemInformation(JDialog parent, boolean bModal)
	{
		this(parent, m_res.getString("DSystemInformation.Title"), bModal);
	}

	/**
	 * Creates new DSystemInformation dialog where the parent is a dialog.
	 * 
	 * @param parent Parent dialog
	 * @param sTitle The title of the dialog
	 * @param bModal Is dialog modal?
	 */
	public DSystemInformation(JDialog parent, String sTitle, boolean bModal)
	{
		super(parent, sTitle, bModal);
		initComponents();
	}

	/**
	 * Initialise the dialog's GUI components.
	 */
	private void initComponents()
	{
		getContentPane().setLayout(new BorderLayout());

		// Get the Java system properties
		Properties sysProps = java.lang.System.getProperties();

		// Get the runtime (to access free/total memory values)
		Runtime runtime = Runtime.getRuntime();

		// Grid Bag Constraints templates for system information
		// labels and text fields
		GridBagConstraints gbcLabel = new GridBagConstraints();
		gbcLabel.gridx = 0;
		gbcLabel.gridwidth = 3;
		gbcLabel.gridheight = 1;
		gbcLabel.insets = new Insets(5, 5, 5, 5);
		gbcLabel.anchor = GridBagConstraints.EAST;

		GridBagConstraints gbcTextField = new GridBagConstraints();
		gbcTextField.gridx = 3;
		gbcTextField.gridwidth = 3;
		gbcTextField.gridheight = 1;
		gbcTextField.insets = new Insets(5, 5, 5, 5);
		gbcTextField.anchor = GridBagConstraints.WEST;

		JPanel jpSystemInformation = new JPanel(new GridBagLayout());
		jpSystemInformation.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		// Operating System
		JLabel jlOperatingSystem =
		    new JLabel(m_res.getString("DSystemInformation.jlOperatingSystem.text"), JLabel.RIGHT);

		GridBagConstraints gbc_jlOperatingSystem = (GridBagConstraints) gbcLabel.clone();
		gbc_jlOperatingSystem.gridy = 0;
		jpSystemInformation.add(jlOperatingSystem, gbc_jlOperatingSystem);

		JTextField jtfOperatingSystem =
		    new JTextField(MessageFormat.format(
		        m_res.getString("DSystemInformation.jtfOperatingSystem.text"), new Object[] {
		            sysProps.getProperty("os.name", ""), sysProps.getProperty("os.version", ""),
		            sysProps.getProperty("os.arch", "") }), VALUE_WIDTH);
		jtfOperatingSystem.setEditable(false);
		jtfOperatingSystem.setCaretPosition(0);

		GridBagConstraints gbc_jtfOperatingSystem = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfOperatingSystem.gridy = 0;
		jpSystemInformation.add(jtfOperatingSystem, gbc_jtfOperatingSystem);

		// Locale
		JLabel jlLocale = new JLabel(m_res.getString("DSystemInformation.jlLocale.text"), JLabel.RIGHT);

		GridBagConstraints gbc_jlLocale = (GridBagConstraints) gbcLabel.clone();
		gbc_jlLocale.gridy = 1;
		jpSystemInformation.add(jlLocale, gbc_jlLocale);

		JTextField jtfLocale = new JTextField(Locale.getDefault().getDisplayName(), VALUE_WIDTH);
		jtfLocale.setEditable(false);
		jtfLocale.setCaretPosition(0);

		GridBagConstraints gbc_jtfLocale = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfLocale.gridy = 1;
		jpSystemInformation.add(jtfLocale, gbc_jtfLocale);

		// Java Version
		JLabel jlJavaVersion =
		    new JLabel(m_res.getString("DSystemInformation.jlJavaVersion.text"), JLabel.RIGHT);

		GridBagConstraints gbc_jlJavaVersion = (GridBagConstraints) gbcLabel.clone();
		gbc_jlJavaVersion.gridy = 2;
		jpSystemInformation.add(jlJavaVersion, gbc_jlJavaVersion);

		JTextField jtfJavaVersion = new JTextField(sysProps.getProperty("java.version", ""), VALUE_WIDTH);
		jtfJavaVersion.setEditable(false);
		jtfJavaVersion.setCaretPosition(0);

		GridBagConstraints gbc_jtfJavaVersion = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfJavaVersion.gridy = 2;
		jpSystemInformation.add(jtfJavaVersion, gbc_jtfJavaVersion);

		// Java Vendor
		JLabel jlJavaVendor =
		    new JLabel(m_res.getString("DSystemInformation.jlJavaVendor.text"), JLabel.RIGHT);

		GridBagConstraints gbc_jlJavaVendor = (GridBagConstraints) gbcLabel.clone();
		gbc_jlJavaVendor.gridy = 3;
		jpSystemInformation.add(jlJavaVendor, gbc_jlJavaVendor);

		JTextField jtfJavaVendor =
		    new JTextField(MessageFormat.format(m_res.getString("DSystemInformation.jtfJavaVendor.text"),
		        new String[] { sysProps.getProperty("java.vendor", ""),
		            sysProps.getProperty("java.vendor.url", "") }), VALUE_WIDTH);
		jtfJavaVendor.setEditable(false);
		jtfJavaVendor.setCaretPosition(0);

		GridBagConstraints gbc_jtfJavaVendor = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfJavaVendor.gridy = 3;
		jpSystemInformation.add(jtfJavaVendor, gbc_jtfJavaVendor);

		// Java Home
		JLabel jlJavaHome = new JLabel(m_res.getString("DSystemInformation.jlJavaHome.text"), JLabel.RIGHT);

		GridBagConstraints gbc_jlJavaHome = (GridBagConstraints) gbcLabel.clone();
		gbc_jlJavaHome.gridy = 4;
		jpSystemInformation.add(jlJavaHome, gbc_jlJavaHome);

		JTextField jtfJavaHome = new JTextField(sysProps.getProperty("java.home", ""), VALUE_WIDTH);
		jtfJavaHome.setEditable(false);
		jtfJavaHome.setCaretPosition(0);

		GridBagConstraints gbc_jtfJavaHome = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfJavaHome.gridy = 4;
		jpSystemInformation.add(jtfJavaHome, gbc_jtfJavaHome);

		// JVM Maximum memory
		JLabel jlJvmMaximumMemory =
		    new JLabel(m_res.getString("DSystemInformation.jlJvmMaximumMemory.text"), JLabel.RIGHT);

		GridBagConstraints gbc_jlJvmMaximumMemory = (GridBagConstraints) gbcLabel.clone();
		gbc_jlJvmMaximumMemory.gridy = 5;
		jpSystemInformation.add(jlJvmMaximumMemory, gbc_jlJvmMaximumMemory);

		JTextField jtfJvmMaximumMemory =
		    new JTextField(MessageFormat.format(
		        m_res.getString("DSystemInformation.jtfJvmMaximumMemory.text"), new Object[] { new Long(
		            Math.round((double) runtime.maxMemory() / 1024)) }), VALUE_WIDTH);
		jtfJvmMaximumMemory.setEditable(false);
		jtfJvmMaximumMemory.setCaretPosition(0);

		GridBagConstraints gbc_jtfJvmMaximumMemory = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfJvmMaximumMemory.gridy = 5;
		jpSystemInformation.add(jtfJvmMaximumMemory, gbc_jtfJvmMaximumMemory);

		// JVM Total memory
		JLabel jlJvmTotalMemory =
		    new JLabel(m_res.getString("DSystemInformation.jlJvmTotalMemory.text"), JLabel.RIGHT);

		GridBagConstraints gbc_jlJvmTotalMemory = (GridBagConstraints) gbcLabel.clone();
		gbc_jlJvmTotalMemory.gridy = 6;
		jpSystemInformation.add(jlJvmTotalMemory, gbc_jlJvmTotalMemory);

		JTextField jtfJvmTotalMemory =
		    new JTextField(MessageFormat.format(m_res.getString("DSystemInformation.jtfJvmTotalMemory.text"),
		        new Object[] { new Long(Math.round((double) runtime.totalMemory() / 1024)) }), VALUE_WIDTH);
		jtfJvmTotalMemory.setEditable(false);
		jtfJvmTotalMemory.setCaretPosition(0);

		GridBagConstraints gbc_jtfJvmTotalMemory = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfJvmTotalMemory.gridy = 6;
		jpSystemInformation.add(jtfJvmTotalMemory, gbc_jtfJvmTotalMemory);

		// JVM Free memory
		JLabel jlJvmFreeMemory =
		    new JLabel(m_res.getString("DSystemInformation.jlJvmFreeMemory.text"), JLabel.RIGHT);

		GridBagConstraints gbc_jlJvmFreeMemory = (GridBagConstraints) gbcLabel.clone();
		gbc_jlJvmFreeMemory.gridy = 7;
		jpSystemInformation.add(jlJvmFreeMemory, gbc_jlJvmFreeMemory);

		JTextField jtfJvmFreeMemory =
		    new JTextField(MessageFormat.format(m_res.getString("DSystemInformation.jtfJvmFreeMemory.text"),
		        new Object[] { new Long(Math.round((double) runtime.freeMemory() / 1024)) }), VALUE_WIDTH);
		jtfJvmFreeMemory.setEditable(false);
		jtfJvmFreeMemory.setCaretPosition(0);

		GridBagConstraints gbc_jtfJvmFreeMemory = (GridBagConstraints) gbcTextField.clone();
		gbc_jtfJvmFreeMemory.gridy = 7;
		jpSystemInformation.add(jtfJvmFreeMemory, gbc_jtfJvmFreeMemory);

		// SystemProperties button
		JButton jbSystemProperties =
		    new JButton(m_res.getString("DSystemInformation.jbSystemProperties.text"));
		jbSystemProperties.setMnemonic(m_res.getString("DSystemInformation.jbSystemProperties.mnemonic").charAt(
		    0));
		jbSystemProperties.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				systemPropertiesPressed();
			}
		});

		// OK button
		JButton jbOK = new JButton(m_res.getString("DSystemInformation.jbOK.text"));
		jbOK.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent evt)
			{
				okPressed();
			}
		});

		JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpButtons.setBorder(new EmptyBorder(5, 0, 5, 0));

		jpButtons.add(jbOK);
		jpButtons.add(jbSystemProperties);

		// Put property and button controls together
		getContentPane().add(jpSystemInformation, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		// Annoying, but resizing wreaks havoc here
		setResizable(false);

		addWindowListener(new WindowAdapter()
		{
			public void windowClosing(WindowEvent evt)
			{
				closeDialog();
			}
		});

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	/**
	 * System properties button pressed or otherwise activated.
	 */
	private void systemPropertiesPressed()
	{
		// Show System Properties dialog
		DSystemProperties dSystemProperties = new DSystemProperties(this, true);
		dSystemProperties.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dSystemProperties);
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
