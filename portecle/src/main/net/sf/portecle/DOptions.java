/*
 * DOptions.java
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

package net.sf.portecle;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.util.ResourceBundle;
import java.util.TreeSet;
import java.util.Vector;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.LookAndFeel;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;

/**
 * Dialog to allow the users to configure Portecle options CA Certs KeyStore
 * and Look & Feel.
 */
class DOptions extends JDialog
{
    /** Key from input map to action map for the cancel button */
    private static final String CANCEL_KEY = "CANCEL_KEY";

    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Tabbed Pane to hold the oprions */
    private JTabbedPane m_jtpOptions;

    /** Panel for CA Certs options components */
    private JPanel m_jpCaCerts;

    /** Subpanel to hold use CA certs components */
    private JPanel m_jpUseCaCerts;

    /** Use CA Certs check box */
    private JCheckBox m_jcbUseCaCerts;

    /** Subpanel to hold use CA certs file components */
    private JPanel m_jpCaCertsFile;

    /** CA certs file label */
    private JLabel m_jlCaCertsFile;

    /** CA certs file text field */
    private JTextField m_jtfCaCertsFile;

    /** Browse button used to select the CA certs file */
    private JButton m_jbBrowseCaCertsFile;

    /** Panel for look & feel options components */
    private JPanel m_jpLookFeel;

    /** Subpanel to hold note regarding look & feel */
    private JPanel m_jpLookFeelNote;

    /** label to hold note regarding look & feel */
    private JLabel m_jlLookFeelNote;

    /** Subpanel for look & feel choice controls */
    private JPanel m_jpLookFeelControls;

    /** Look & feel label */
    private JLabel m_jlLookFeel;

    /** Look & feel combo box */
    private JComboBox m_jcbLookFeel;

    /** Subpanel for look & feel decorated setting controls */
    private JPanel m_jpLookFeelDecoratedControls;

    /** Look & feel decorated check box */
    private JCheckBox m_jcbLookFeelDecorated;

    /** Panel for confirmation button controls */
    private JPanel m_jpButtons;

    /** OK button to confirm dialog */
    private JButton m_jbOK;

    /** Cancel button to cancel dialog */
    private JButton m_jbCancel;

    /** Use CA Certs KeyStore file? */
    private boolean m_bUseCaCerts;

    /** Chosen CA Certs KeyStore file */
    private File m_fCaCertsFile;

    /** Available Look and Feel information - reflects what is in choice box */
    private Vector m_vLookFeelInfos = new Vector();

    /** Chosen look & feel information */
    private UIManager.LookAndFeelInfo m_lookFeelInfo;

    /** Use look & feel for window decoration? */
    private boolean m_bLookFeelDecorated;

    /**
     * Creates new form DOptions where the parent is a frame.
     *
     * @param parent The parent frame
     * @param bModal Is dialog modal?
     * @param bUseCaCerts Use CA Certs keystore file?
     * @param fCaCertsFile CA Certs keystore file
     */
    public DOptions(JFrame parent, boolean bModal, boolean bUseCaCerts,
                    File fCaCertsFile)
    {
        super(parent, bModal);
        m_bUseCaCerts = bUseCaCerts;
        m_fCaCertsFile = fCaCertsFile;
        initComponents();
    }

    /**
     * Initialise the dialog's GUI components.
     */
    private void initComponents()
    {
        // Setup tabbed panels of options

        // CA Certs options tab panel
        m_jcbUseCaCerts = new JCheckBox(
            m_res.getString("DOptions.m_jcbUseCaCerts.text"), m_bUseCaCerts);
        m_jcbUseCaCerts.setToolTipText(
            m_res.getString("DOptions.m_jcbUseCaCerts.tooltip"));

        m_jpUseCaCerts = new JPanel(new FlowLayout(FlowLayout.LEFT));
        m_jpUseCaCerts.add(m_jcbUseCaCerts);

        m_jlCaCertsFile = new JLabel(
            m_res.getString("DOptions.m_jlCaCertsFile.text"));
        m_jtfCaCertsFile = new JTextField(m_fCaCertsFile.toString(), 20);
        m_jtfCaCertsFile.setToolTipText(
            m_res.getString("DOptions.m_jtfCaCertsFile.tooltip"));
        m_jtfCaCertsFile.setCaretPosition(0);
        m_jtfCaCertsFile.setEditable(false);
        m_jpCaCertsFile = new JPanel(new FlowLayout(FlowLayout.LEFT));
        m_jpCaCertsFile.add(m_jlCaCertsFile);
        m_jpCaCertsFile.add(m_jtfCaCertsFile);

        m_jbBrowseCaCertsFile = new JButton(
            m_res.getString("DOptions.m_jbBrowseCaCertsFile.text"));
        m_jbBrowseCaCertsFile.setMnemonic(
            m_res.getString("DOptions.m_jbBrowseCaCertsFile.mnemonic")
            .charAt(0));
        m_jbBrowseCaCertsFile.setToolTipText(
            m_res.getString("DOptions.m_jbBrowseCaCertsFile.tooltip"));
        m_jbBrowseCaCertsFile.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt)
            {
                browsePressed();
            }
        });
        m_jpCaCertsFile.add(m_jbBrowseCaCertsFile);

        m_jpCaCerts = new JPanel(new GridLayout(2, 1));
        m_jpCaCerts.add(m_jpUseCaCerts);
        m_jpCaCerts.add(m_jpCaCertsFile);

        // Look & feel tabbed options tab panel
        m_jlLookFeelNote = new JLabel(
            m_res.getString("DOptions.m_jlLookFeelNote.text"));

        // Note
        m_jpLookFeelNote = new JPanel(new FlowLayout(FlowLayout.LEFT));
        m_jpLookFeelNote.add(m_jlLookFeelNote);

        m_jlLookFeel = new JLabel(
            m_res.getString("DOptions.m_jlLookFeel.text"));

        // Create and populate combo box with available look & feels
        m_jcbLookFeel = new JComboBox();
        m_jcbLookFeel.setToolTipText(
            m_res.getString("DOptions.m_jcbLookFeel.tooltip"));

        // All Look and Feels (may contain duplicates)
        UIManager.LookAndFeelInfo[] lookFeelInfos =
            UIManager.getInstalledLookAndFeels();

        // Current Look and Feel
        LookAndFeel currentLookAndFeel = UIManager.getLookAndFeel();

        // Set of installed and supported Look and Feel class names
        TreeSet lookFeelClasses = new TreeSet();

        for (int iCnt=0; iCnt < lookFeelInfos.length; iCnt++)
        {
            UIManager.LookAndFeelInfo lookFeelInfo = lookFeelInfos[iCnt];
            String className = lookFeelInfo.getClassName();

            // Avoid duplicates, optimize
            if (lookFeelClasses.contains(className))
            {
                continue;
            }

            // Check if it's a supported one (eg. Windows on Linux is not)
            boolean bSupported = false;
            try
            {
                bSupported = ((LookAndFeel) Class.forName(className)
                              .newInstance()).isSupportedLookAndFeel();
            }
            catch (Exception e) { /* Ignore */ }
            if (bSupported)
            {
                lookFeelClasses.add(className);
            }
            else
            {
                continue;
            }

            // Add Look and Feel to vector and choice box (so we can look up
            // Look and Feel in Vector by choice box index).
            m_vLookFeelInfos.add(lookFeelInfo);
            m_jcbLookFeel.addItem(lookFeelInfo.getName());

            // Pre-select current look & feel
            /* Note: UIManager.LookAndFeelInfo.getName() and
               LookAndFeel.getName() can be different for the same L&F (one
               example is the GTK+ one in J2SE 5 RC2 (Linux), where the former
               is "GTK+" and the latter is "GTK look and feel"). Therefore,
               compare the class names instead. */
            if (currentLookAndFeel != null &&
                currentLookAndFeel.getClass().getName().equals(
                    lookFeelInfo.getClassName()))
                {
                m_jcbLookFeel.setSelectedIndex(
                    m_jcbLookFeel.getItemCount() - 1);
            }
        }

        m_jpLookFeelControls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        m_jpLookFeelControls.add(m_jlLookFeel);
        m_jpLookFeelControls.add(m_jcbLookFeel);

        // Create and populate check box with look & feel decorated setting
        m_jcbLookFeelDecorated = new JCheckBox(
            m_res.getString("DOptions.m_jcbLookFeelDecorated.text"),
            JFrame.isDefaultLookAndFeelDecorated());
        m_jcbLookFeelDecorated.setToolTipText(
            m_res.getString("DOptions.m_jcbLookFeelDecorated.tooltip"));

        m_jpLookFeelDecoratedControls = new JPanel(
            new FlowLayout(FlowLayout.LEFT));
        m_jpLookFeelDecoratedControls.add(m_jcbLookFeelDecorated);

        m_jpLookFeel = new JPanel(new BorderLayout());
        m_jpLookFeel.add(m_jpLookFeelNote, BorderLayout.NORTH);
        m_jpLookFeel.add(m_jpLookFeelControls, BorderLayout.CENTER);
        m_jpLookFeel.add(m_jpLookFeelDecoratedControls, BorderLayout.SOUTH);

        // Add the panels to a tabbed pane
        m_jtpOptions = new JTabbedPane();
        m_jtpOptions.addTab(
            m_res.getString("DOptions.m_jpCaCerts.text"), null, m_jpCaCerts,
            m_res.getString("DOptions.m_jpCaCerts.tooltip"));
        m_jtpOptions.addTab(
            m_res.getString("DOptions.m_jpLookFeel.text"), null, m_jpLookFeel,
            m_res.getString("DOptions.m_jpLookFeel.tooltip"));
        m_jtpOptions.setBorder(new EmptyBorder(5, 5, 5, 5));

        // OK and Cancel buttons
        m_jbOK = new JButton(m_res.getString("DOptions.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        m_jbCancel = new JButton(m_res.getString("DOptions.m_jbCancel.text"));
        m_jbCancel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });
        m_jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);
        m_jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction () {
                public void actionPerformed(ActionEvent evt) {
                    cancelPressed();
                }});

        m_jpButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        m_jpButtons.add(m_jbOK);
        m_jpButtons.add(m_jbCancel);

        // Put it all together
        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(m_jtpOptions, BorderLayout.CENTER);
        getContentPane().add(m_jpButtons, BorderLayout.SOUTH);

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        setTitle(m_res.getString("DOptions.Title"));
        setResizable(false);

        getRootPane().setDefaultButton(m_jbOK);

        pack();
    }

    /**
     * Store the user's option choices.
     */
    private void storeOptions()
    {
        // Store CA Certs file
        m_fCaCertsFile = new File(m_jtfCaCertsFile.getText());

        // Store whether or not to use CA Certs KeyStore
        m_bUseCaCerts = m_jcbUseCaCerts.isSelected();

        // Store look & feel class name (look up in Vector by choice box index)
        int iSel = m_jcbLookFeel.getSelectedIndex();
        m_lookFeelInfo = (UIManager.LookAndFeelInfo)m_vLookFeelInfos.get(iSel);

        // Store whether or not look & feel decoration should be used
        m_bLookFeelDecorated = m_jcbLookFeelDecorated.isSelected();
    }

    /**
     * Get the chosen CA Certs KeyStore file.
     *
     * @return The chosen CA Certs KeyStore file
     */
    public File getCaCertsFile()
    {
        return m_fCaCertsFile;
    }

    /**
     * Get whether or not the usage of CA Certs has been chosen.
     *
     * @return True if it has, false otherwise
     */
    public boolean getUseCaCerts()
    {
        return m_bUseCaCerts;
    }

    /**
     * Get the chosen look & feel information.
     *
     * @return The chosen look & feel information
     */
    public UIManager.LookAndFeelInfo getLookFeelInfo()
    {
        return m_lookFeelInfo;
    }

    /**
     * Get whether or not the look & feel should be used for window decoration.
     *
     * @return True id it should, false otherwise.
     */
    public boolean getLookFeelDecoration()
    {
        return m_bLookFeelDecorated;
    }

    /**
     * Browse button pressed or otherwise activated.  Allow the user to
     * choose a CA Certs file.
     */
    private void browsePressed()
    {
        JFileChooser chooser = FileChooserFactory.getKeyStoreFileChooser();

        if (m_fCaCertsFile.getParentFile().exists())
        {
            chooser.setCurrentDirectory(m_fCaCertsFile.getParentFile());
        }

        chooser.setDialogTitle(
            m_res.getString("DOptions.ChooseCACertsKeyStore.Title"));

        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(
            this,
            m_res.getString("DOptions.CaCertsKeyStoreFileChooser.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION)
        {
            m_jtfCaCertsFile.setText(chooser.getSelectedFile().toString());
            m_jtfCaCertsFile.setCaretPosition(0);
        }
    }

    /**
     * OK button pressed or otherwise activated.  Store the
     * user's option choices and close the dialog.
     */
    private void okPressed()
    {
        storeOptions();
        closeDialog();
    }

    /**
     * Cancel button pressed or otherwise activated.
     */
    private void cancelPressed()
    {
        closeDialog();
    }

    /**
     * Closes the dialog.
     */
    private void closeDialog()
    {
        setVisible(false);
        dispose();
    }
}
