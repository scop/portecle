/*
 * DSystemInformation.java
 *
 * Copyright (C) 2004 Wayne Grant
 * waynedgrant@hotmail.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * (This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

package net.sf.portecle.gui.about;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.text.MessageFormat;

/**
 * A dialog which displays general system information:
 * OS, Locale, Java version, Java vendor, Java vendor URL,
 * JVM total memory and JVM free memory.
 */
public class DSystemInformation extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/gui/about/resources");

    /** Panel containing system information */
    private JPanel m_jpSystemInformation;

    /** Operating System label */
    private JLabel m_jlOperatingSystem;

    /** Operating System text field */
    private JTextField m_jtfOperatingSystem;

    /** Locale label */
    private JLabel m_jlLocale;

    /** Locale text field */
    private JTextField m_jtfLocale;

    /** Java Version label */
    private JLabel m_jlJavaVersion;

    /** Java Version text field */
    private JTextField m_jtfJavaVersion;

    /** Java Vendor label */
    private JLabel m_jlJavaVendor;

    /** Java Vendor text field */
    private JTextField m_jtfJavaVendor;

    /** Java Home label */
    private JLabel m_jlJavaHome;

    /** Java Home text field */
    private JTextField m_jtfJavaHome;

    /** Maximum Memory label */
    private JLabel m_jlJvmMaximumMemory;

    /** Maximum Memory text field */
    private JTextField m_jtfJvmMaximumMemory;

    /** Total Memory label */
    private JLabel m_jlJvmTotalMemory;

    /** Total Memory text field */
    private JTextField m_jtfJvmTotalMemory;

    /** Free Memory label */
    private JLabel m_jlJvmFreeMemory;

    /** Free Memory text field */
    private JTextField m_jtfJvmFreeMemory;

    /** OK button used to display system properties */
    private JButton m_jbSystemProperties;

    /** OK button used to dismiss dialog */
    private JButton m_jbOK;

    /** Panel containing buttons */
    private JPanel m_jpButtons;

    /** Width of system information text fields */
    private static final int VALUE_WIDTH = 25;

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
     *
     */
    private void initComponents()
    {
        getContentPane().setLayout(new BorderLayout());

        // Get the Java system properties
        Properties sysProps = java.lang.System.getProperties();

        // Get the runtime (to access free/total memory values)
        Runtime runtime = Runtime.getRuntime();

        // Grid Bag Constraints templates for system information labels and text fields
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

        m_jpSystemInformation = new JPanel(new GridBagLayout());
        m_jpSystemInformation.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5),
                                                           new EtchedBorder()));


        // Operating System
        JLabel m_jlOperatingSystem = new JLabel(m_res.getString("DSystemInformation.m_jlOperatingSystem.text"), JLabel.RIGHT);

        GridBagConstraints gbc_jlOperatingSystem = (GridBagConstraints)gbcLabel.clone();
        gbc_jlOperatingSystem.gridy = 0;
        m_jpSystemInformation.add(m_jlOperatingSystem, gbc_jlOperatingSystem);

        m_jtfOperatingSystem = new JTextField(MessageFormat.format(m_res.getString("DSystemInformation.m_jtfOperatingSystem.text"),
                                                                  new Object[]{sysProps.getProperty("os.name", ""),
                                                                               sysProps.getProperty("os.version", ""),
                                                                               sysProps.getProperty("os.arch", "")}), VALUE_WIDTH);
        m_jtfOperatingSystem.setEditable(false);
        m_jtfOperatingSystem.setCaretPosition(0);

        GridBagConstraints gbc_jtfOperatingSystem = (GridBagConstraints)gbcTextField.clone();
        gbc_jtfOperatingSystem.gridy = 0;
        m_jpSystemInformation.add(m_jtfOperatingSystem, gbc_jtfOperatingSystem);

        // Locale
        JLabel m_jlLocale = new JLabel(m_res.getString("DSystemInformation.m_jlLocale.text"), JLabel.RIGHT);

        GridBagConstraints gbc_jlLocale = (GridBagConstraints)gbcLabel.clone();
        gbc_jlLocale.gridy = 1;
        m_jpSystemInformation.add(m_jlLocale, gbc_jlLocale);

        m_jtfLocale = new JTextField(Locale.getDefault().getDisplayName(), VALUE_WIDTH);
        m_jtfLocale.setEditable(false);
        m_jtfLocale.setCaretPosition(0);

        GridBagConstraints gbc_jtfLocale = (GridBagConstraints)gbcTextField.clone();
        gbc_jtfLocale.gridy = 1;
        m_jpSystemInformation.add(m_jtfLocale, gbc_jtfLocale);

        // Java Version
        JLabel m_jlJavaVersion = new JLabel(m_res.getString("DSystemInformation.m_jlJavaVersion.text"), JLabel.RIGHT);

        GridBagConstraints gbc_jlJavaVersion = (GridBagConstraints)gbcLabel.clone();
        gbc_jlJavaVersion.gridy = 2;
        m_jpSystemInformation.add(m_jlJavaVersion, gbc_jlJavaVersion);

        m_jtfJavaVersion = new JTextField(sysProps.getProperty("java.version", ""), VALUE_WIDTH);
        m_jtfJavaVersion.setEditable(false);
        m_jtfJavaVersion.setCaretPosition(0);

        GridBagConstraints gbc_jtfJavaVersion = (GridBagConstraints)gbcTextField.clone();
        gbc_jtfJavaVersion.gridy = 2;
        m_jpSystemInformation.add(m_jtfJavaVersion, gbc_jtfJavaVersion);

        // Java Vendor
        JLabel m_jlJavaVendor = new JLabel(m_res.getString("DSystemInformation.m_jlJavaVendor.text"), JLabel.RIGHT);

        GridBagConstraints gbc_jlJavaVendor = (GridBagConstraints)gbcLabel.clone();
        gbc_jlJavaVendor.gridy = 3;
        m_jpSystemInformation.add(m_jlJavaVendor, gbc_jlJavaVendor);

        m_jtfJavaVendor = new JTextField(MessageFormat.format(m_res.getString("DSystemInformation.m_jtfJavaVendor.text"),
                                                              new String[]{sysProps.getProperty("java.vendor", ""),
                                                                           sysProps.getProperty("java.vendor.url", "")}), VALUE_WIDTH);
        m_jtfJavaVendor.setEditable(false);
        m_jtfJavaVendor.setCaretPosition(0);

        GridBagConstraints gbc_jtfJavaVendor = (GridBagConstraints)gbcTextField.clone();
        gbc_jtfJavaVendor.gridy = 3;
        m_jpSystemInformation.add(m_jtfJavaVendor, gbc_jtfJavaVendor);

        // Java Home
        JLabel m_jlJavaHome = new JLabel(m_res.getString("DSystemInformation.m_jlJavaHome.text"), JLabel.RIGHT);

        GridBagConstraints gbc_jlJavaHome = (GridBagConstraints)gbcLabel.clone();
        gbc_jlJavaHome.gridy = 4;
        m_jpSystemInformation.add(m_jlJavaHome, gbc_jlJavaHome);

        m_jtfJavaHome = new JTextField(sysProps.getProperty("java.home", ""), VALUE_WIDTH);
        m_jtfJavaHome.setEditable(false);
        m_jtfJavaHome.setCaretPosition(0);

        GridBagConstraints gbc_jtfJavaHome = (GridBagConstraints)gbcTextField.clone();
        gbc_jtfJavaHome.gridy = 4;
        m_jpSystemInformation.add(m_jtfJavaHome, gbc_jtfJavaHome);

        // JVM Maximum memory
        m_jlJvmMaximumMemory = new JLabel(m_res.getString("DSystemInformation.m_jlJvmMaximumMemory.text"), JLabel.RIGHT);

        GridBagConstraints gbc_jlJvmMaximumMemory = (GridBagConstraints)gbcLabel.clone();
        gbc_jlJvmMaximumMemory.gridy = 5;
        m_jpSystemInformation.add(m_jlJvmMaximumMemory, gbc_jlJvmMaximumMemory);

        m_jtfJvmMaximumMemory = new JTextField(MessageFormat.format(m_res.getString("DSystemInformation.m_jtfJvmMaximumMemory.text"),
                                                                 new Object[]{new Integer(Math.round(runtime.maxMemory() / 1024))}), VALUE_WIDTH);
        m_jtfJvmMaximumMemory.setEditable(false);
        m_jtfJvmMaximumMemory.setCaretPosition(0);

        GridBagConstraints gbc_jtfJvmMaximumMemory = (GridBagConstraints)gbcTextField.clone();
        gbc_jtfJvmMaximumMemory.gridy = 5;
        m_jpSystemInformation.add(m_jtfJvmMaximumMemory, gbc_jtfJvmMaximumMemory);

        // JVM Total memory
        JLabel m_jlJvmTotalMemory = new JLabel(m_res.getString("DSystemInformation.m_jlJvmTotalMemory.text"), JLabel.RIGHT);

        GridBagConstraints gbc_jlJvmTotalMemory = (GridBagConstraints)gbcLabel.clone();
        gbc_jlJvmTotalMemory.gridy = 6;
        m_jpSystemInformation.add(m_jlJvmTotalMemory, gbc_jlJvmTotalMemory);

        m_jtfJvmTotalMemory = new JTextField(MessageFormat.format(m_res.getString("DSystemInformation.m_jtfJvmTotalMemory.text"),
                                                                  new Object[]{new Integer(Math.round(runtime.totalMemory() / 1024))}), VALUE_WIDTH);
        m_jtfJvmTotalMemory.setEditable(false);
        m_jtfJvmTotalMemory.setCaretPosition(0);

        GridBagConstraints gbc_jtfJvmTotalMemory = (GridBagConstraints)gbcTextField.clone();
        gbc_jtfJvmTotalMemory.gridy = 6;
        m_jpSystemInformation.add(m_jtfJvmTotalMemory, gbc_jtfJvmTotalMemory);

        // JVM Free memory
        m_jlJvmFreeMemory = new JLabel(m_res.getString("DSystemInformation.m_jlJvmFreeMemory.text"), JLabel.RIGHT);

        GridBagConstraints gbc_jlJvmFreeMemory = (GridBagConstraints)gbcLabel.clone();
        gbc_jlJvmFreeMemory.gridy = 7;
        m_jpSystemInformation.add(m_jlJvmFreeMemory, gbc_jlJvmFreeMemory);

        m_jtfJvmFreeMemory = new JTextField(MessageFormat.format(m_res.getString("DSystemInformation.m_jtfJvmFreeMemory.text"),
                                                                 new Object[]{new Integer(Math.round(runtime.freeMemory() / 1024))}), VALUE_WIDTH);
        m_jtfJvmFreeMemory.setEditable(false);
        m_jtfJvmFreeMemory.setCaretPosition(0);

        GridBagConstraints gbc_jtfJvmFreeMemory = (GridBagConstraints)gbcTextField.clone();
        gbc_jtfJvmFreeMemory.gridy = 7;
        m_jpSystemInformation.add(m_jtfJvmFreeMemory, gbc_jtfJvmFreeMemory);

        // SystemProperties button
        m_jbSystemProperties = new JButton(m_res.getString("DSystemInformation.m_jbSystemProperties.text"));
        m_jbSystemProperties.setMnemonic(m_res.getString("DSystemInformation.m_jbSystemProperties.mnemonic").charAt(0));
        m_jbSystemProperties.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                systemPropertiesPressed();
            }
        });

        // OK button
        m_jbOK = new JButton(m_res.getString("DSystemInformation.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        m_jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
        m_jpButtons.setBorder(new EmptyBorder(5, 0, 5, 0));

        m_jpButtons.add(m_jbOK);
        m_jpButtons.add(m_jbSystemProperties);

        // Put property and button controls together
        getContentPane().add(m_jpSystemInformation, BorderLayout.CENTER);
        getContentPane().add(m_jpButtons, BorderLayout.SOUTH);

        // Annoying, but resizing wreaks havoc here
        setResizable(false);

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        getRootPane().setDefaultButton(m_jbOK);

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
        dSystemProperties.setVisible(true);
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
