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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
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
 * Dialog to allow the users to configure Portecle options, CA certs keystore,
 * and look & feel.
 */
class DOptions
    extends JDialog
{
    /** Key from input map to action map for the cancel button */
    private static final String CANCEL_KEY = "CANCEL_KEY";

    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Use CA certs check box */
    private JCheckBox m_jcbUseCaCerts;

    /** CA certs file text field */
    private JTextField m_jtfCaCertsFile;

    /** Look & feel combo box */
    private JComboBox m_jcbLookFeel;

    /** Look & feel decorated check box */
    private JCheckBox m_jcbLookFeelDecorated;

    /** Use CA certs keystore file? */
    private boolean m_bUseCaCerts;

    /** Chosen CA certs keystore file */
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
     * @param bUseCaCerts Use CA certs keystore file?
     * @param fCaCertsFile CA certs keystore file
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

        // CA certs options tab panel
        m_jcbUseCaCerts = new JCheckBox(
            m_res.getString("DOptions.m_jcbUseCaCerts.text"), m_bUseCaCerts);
        m_jcbUseCaCerts.setToolTipText(m_res.getString("DOptions.m_jcbUseCaCerts.tooltip"));

        JPanel jpUseCaCerts = new JPanel(new FlowLayout(FlowLayout.LEFT));
        jpUseCaCerts.add(m_jcbUseCaCerts);

        JLabel jlCaCertsFile = new JLabel(
            m_res.getString("DOptions.jlCaCertsFile.text"));
        m_jtfCaCertsFile = new JTextField(m_fCaCertsFile.toString(), 20);
        m_jtfCaCertsFile.setToolTipText(m_res.getString("DOptions.m_jtfCaCertsFile.tooltip"));
        m_jtfCaCertsFile.setCaretPosition(0);
        m_jtfCaCertsFile.setEditable(false);
        JPanel jpCaCertsFile = new JPanel(new FlowLayout(FlowLayout.LEFT));
        jpCaCertsFile.add(jlCaCertsFile);
        jpCaCertsFile.add(m_jtfCaCertsFile);

        JButton jbBrowseCaCertsFile = new JButton(
            m_res.getString("DOptions.jbBrowseCaCertsFile.text"));
        jbBrowseCaCertsFile.setMnemonic(m_res.getString(
            "DOptions.jbBrowseCaCertsFile.mnemonic").charAt(0));
        jbBrowseCaCertsFile.setToolTipText(m_res.getString("DOptions.jbBrowseCaCertsFile.tooltip"));
        jbBrowseCaCertsFile.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                browsePressed();
            }
        });
        jpCaCertsFile.add(jbBrowseCaCertsFile);

        JPanel jpCaCerts = new JPanel(new GridLayout(2, 1));
        jpCaCerts.add(jpUseCaCerts);
        jpCaCerts.add(jpCaCertsFile);

        // Look & feel tabbed options tab panel
        JLabel jlLookFeelNote = new JLabel(
            m_res.getString("DOptions.jlLookFeelNote.text"));

        // Note
        JPanel jpLookFeelNote = new JPanel(new FlowLayout(FlowLayout.LEFT));
        jpLookFeelNote.add(jlLookFeelNote);

        JLabel jlLookFeel = new JLabel(
            m_res.getString("DOptions.jlLookFeel.text"));

        // Create and populate combo box with available look & feels
        m_jcbLookFeel = new JComboBox();
        m_jcbLookFeel.setToolTipText(m_res.getString("DOptions.m_jcbLookFeel.tooltip"));

        // All Look and Feels (may contain duplicates)
        UIManager.LookAndFeelInfo[] lookFeelInfos = UIManager.getInstalledLookAndFeels();

        // Current Look and Feel
        LookAndFeel currentLookAndFeel = UIManager.getLookAndFeel();

        // Set of installed and supported Look and Feel class names
        TreeSet lookFeelClasses = new TreeSet();

        for (int iCnt = 0; iCnt < lookFeelInfos.length; iCnt++) {
            UIManager.LookAndFeelInfo lookFeelInfo = lookFeelInfos[iCnt];
            String className = lookFeelInfo.getClassName();

            // Avoid duplicates, optimize
            if (lookFeelClasses.contains(className)) {
                continue;
            }

            // Check if it's a supported one (eg. Windows on Linux is not)
            boolean bSupported = false;
            try {
                bSupported = ((LookAndFeel) Class.forName(className).newInstance()).isSupportedLookAndFeel();
            }
            catch (Exception e) { /* Ignore */
            }
            if (bSupported) {
                lookFeelClasses.add(className);
            }
            else {
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
            if (currentLookAndFeel != null
                && currentLookAndFeel.getClass().getName().equals(
                    lookFeelInfo.getClassName()))
            {
                m_jcbLookFeel.setSelectedIndex(m_jcbLookFeel.getItemCount() - 1);
            }
        }

        JPanel jpLookFeelControls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        jpLookFeelControls.add(jlLookFeel);
        jpLookFeelControls.add(m_jcbLookFeel);

        // Create and populate check box with look & feel decorated setting
        m_jcbLookFeelDecorated = new JCheckBox(
            m_res.getString("DOptions.m_jcbLookFeelDecorated.text"),
            JFrame.isDefaultLookAndFeelDecorated());
        m_jcbLookFeelDecorated.setToolTipText(m_res.getString("DOptions.m_jcbLookFeelDecorated.tooltip"));

        JPanel jpLookFeelDecoratedControls = new JPanel(new FlowLayout(
            FlowLayout.LEFT));
        jpLookFeelDecoratedControls.add(m_jcbLookFeelDecorated);

        JPanel jpLookFeel = new JPanel(new BorderLayout());
        jpLookFeel.add(jpLookFeelNote, BorderLayout.NORTH);
        jpLookFeel.add(jpLookFeelControls, BorderLayout.CENTER);
        jpLookFeel.add(jpLookFeelDecoratedControls, BorderLayout.SOUTH);

        // Add the panels to a tabbed pane
        JTabbedPane jtpOptions = new JTabbedPane();
        jtpOptions.addTab(m_res.getString("DOptions.jpCaCerts.text"), null,
            jpCaCerts, m_res.getString("DOptions.jpCaCerts.tooltip"));
        jtpOptions.addTab(m_res.getString("DOptions.jpLookFeel.text"), null,
            jpLookFeel, m_res.getString("DOptions.jpLookFeel.tooltip"));
        jtpOptions.setBorder(new EmptyBorder(5, 5, 5, 5));

        // OK and Cancel buttons
        JButton jbOK = new JButton(m_res.getString("DOptions.jbOK.text"));
        jbOK.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                okPressed();
            }
        });

        JButton jbCancel = new JButton(
            m_res.getString("DOptions.jbCancel.text"));
        jbCancel.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                cancelPressed();
            }
        });
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);
        jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction()
        {
            public void actionPerformed(ActionEvent evt)
            {
                cancelPressed();
            }
        });

        JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        jpButtons.add(jbOK);
        jpButtons.add(jbCancel);

        // Put it all together
        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(jtpOptions, BorderLayout.CENTER);
        getContentPane().add(jpButtons, BorderLayout.SOUTH);

        addWindowListener(new WindowAdapter()
        {
            public void windowClosing(WindowEvent evt)
            {
                closeDialog();
            }
        });

        setTitle(m_res.getString("DOptions.Title"));
        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    /**
     * Store the user's option choices.
     */
    private void storeOptions()
    {
        // Store CA certs file
        m_fCaCertsFile = new File(m_jtfCaCertsFile.getText());

        // Store whether or not to use CA certs keystore
        m_bUseCaCerts = m_jcbUseCaCerts.isSelected();

        // Store look & feel class name (look up in Vector by choice box index)
        int iSel = m_jcbLookFeel.getSelectedIndex();
        m_lookFeelInfo = (UIManager.LookAndFeelInfo) m_vLookFeelInfos.get(iSel);

        // Store whether or not look & feel decoration should be used
        m_bLookFeelDecorated = m_jcbLookFeelDecorated.isSelected();
    }

    /**
     * Get the chosen CA certs keystore file.
     *
     * @return The chosen CA certs keystore file
     */
    public File getCaCertsFile()
    {
        return m_fCaCertsFile;
    }

    /**
     * Get whether or not the usage of CA certs has been chosen.
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
     * choose a CA certs file.
     */
    private void browsePressed()
    {
        JFileChooser chooser = FileChooserFactory.getKeyStoreFileChooser();

        if (m_fCaCertsFile.getParentFile().exists()) {
            chooser.setCurrentDirectory(m_fCaCertsFile.getParentFile());
        }

        chooser.setDialogTitle(m_res.getString("DOptions.ChooseCACertsKeyStore.Title"));

        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this,
            m_res.getString("DOptions.CaCertsKeyStoreFileChooser.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
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
