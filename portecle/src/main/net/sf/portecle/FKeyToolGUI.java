/*
 * FKeyToolGUI.java
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

package net.sf.portecle;

import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import java.text.MessageFormat;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.plaf.metal.MetalLookAndFeel;
import javax.swing.table.*;
import javax.swing.text.*;
import javax.swing.text.html.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.net.*;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x509.*;

import edu.stanford.ejalbert.BrowserLauncher;

import net.sf.portecle.crypto.*;
import net.sf.portecle.gui.*;
import net.sf.portecle.gui.about.DAbout;
import net.sf.portecle.gui.crypto.DProviderInfo;
import net.sf.portecle.gui.error.DThrowable;
import net.sf.portecle.gui.help.FHelp;
import net.sf.portecle.gui.jar.DJarInfo;
import net.sf.portecle.gui.password.*;
import net.sf.portecle.gui.statusbar.*;
import net.sf.portecle.gui.theme.LightMetalTheme;
import net.sf.portecle.version.*;

/**
 * Start class and main frame of the KeyStore GUI application.
 */
public class FKeyToolGUI extends JFrame implements StatusBar
{
    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Minimum required JRE version */
    private static final String REQ_JRE_VERSION = "1.4.0";

    /** Default KeyStore table width - dictates width of this frame */
    private static final int DEFAULT_TABLE_WIDTH = 600;

    /** Default KeyStore table width - dictates height of this frame */
    private static final int DEFAULT_TABLE_HEIGHT = 400;

    /** Number of recent files to hold in the file menu */
    private static final int RECENT_FILES_LENGTH = 4;

    /** Menu index in the file menu for recent files to be inserted at */
    private static final int RECENT_FILES_INDEX = 5;

    /** Default look & feel class name */
    private static final String DEFAULT_LOOK_FEEL = "javax.swing.plaf.metal.MetalLookAndFeel";

    /** Dummy password to use for PKCS #12 KeyStore entries (passwords are not applicable for these) */
    private static final char[] PKCS12_DUMMY_PASSWORD = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};

    /** Use CA Certs KeyStore file? */
    private boolean m_bUseCaCerts;

    /** CA Certs KeyStore file */
    private File m_fCaCertsFile;

    /** CA Certs KeyStore */
    private KeyStore m_caCertsKeyStore;

    /** KeyStore Wrapper object containing the current KeyStore */
    private KeyStoreWrapper m_keyStoreWrap;

    /** The last directory accessed by the application */
    LastDir m_lastDir = new LastDir();

    /** Frame for Help System */
    private FHelp m_fHelp;

	/** Look & Feel setting made in options (to be picked up by saveAppProps) */
    private UIManager.LookAndFeelInfo m_lookFeelOptions;

	/** Look & Feel setting made in options (to be picked up by saveAppProps) */
    private Boolean m_bLookFeelDecorationOptions;

    ////////////////////////////////////////////////////////////
    // Menu bar controls
    ////////////////////////////////////////////////////////////

    /** Menu bar */
    private JMenuBar m_jmbMenuBar;

    /** File menu */
    private JMenuRecentFiles m_jmrfFile;

    /** New KeyStore menu item of File menu */
    private JMenuItem m_jmiNewKeyStore;

    /** Open KeyStore menu item of File menu */
    private JMenuItem m_jmiOpenKeyStore;

    /** Save KeyStore menu item of File menu */
    private JMenuItem m_jmiSaveKeyStore;

    /** Save KeyStore As menu item of File menu */
    private JMenuItem m_jmiSaveKeyStoreAs;

    /** Exit menu item of File menu */
    private JMenuItem m_jmiExit;

    /** Tools menu */
    private JMenu m_jmTools;

    /** Generate KeyPair menu item of Tools menu */
    private JMenuItem m_jmiGenKeyPair;

    /** Import Trusted Certificate menu item of Tools menu */
    private JMenuItem m_jmiImportTrustCert;

    /** Import KeyPair menu item of Tools menu */
    private JMenuItem m_jmiImportKeyPair;

    /** Change KeyStore Type menu Tools menu */
    private JMenu m_jmChangeKeyStoreType;

    /** JKS menu item in Change KeyStore Type menu */
    private JMenuItem m_jmiChangeKeyStoreTypeJks;

    /** JCEKS menu item in Change KeyStore Type menu */
    private JMenuItem m_jmiChangeKeyStoreTypeJceks;

    /** PKCS#12 menu item in Change KeyStore Type menu */
    private JMenuItem m_jmiChangeKeyStoreTypePkcs12;

    /** BKS menu item in Change KeyStore Type menu */
    private JMenuItem m_jmiChangeKeyStoreTypeBks;

    /** UBER menu item in Change KeyStore Type menu */
    private JMenuItem m_jmiChangeKeyStoreTypeUber;

    /** Set KeyStore Password menu item of Tools menu */
    private JMenuItem m_jmiSetKeyStorePass;

    /** Set KeyStore Report menu item of Tools menu */
    private JMenuItem m_jmiKeyStoreReport;

    /** KeyTool Options menu item of Tools menu */
    private JMenuItem m_jmiOptions;

    /** Examine menu */
    private JMenu m_jmExamine;

    /** Examine Certificate menu item of Examine menu */
    private JMenuItem m_jmiExamineCert;

    /** Examine CRL menu item of Examine menu */
    private JMenuItem m_jmiExamineCrl;

    /** Help menu */
    private JMenu m_jmHelp;

    /** Help menu item of Help menu */
    private JMenuItem m_jmiHelp;

    /** Online Resources menu of Help menu */
    private JMenu m_jmOnlineResources;

    /** KeyTool GUI Website menu item of Online Resources menu */
    private JMenuItem m_jmiWebsite;

    /** Portecle project page at SourceForge.net menu item of Online Resources menu */
    private JMenuItem m_jmiSFNetProject;

    /** KeyTool GUI Email menu item of Online Resources menu */
    private JMenuItem m_jmiEmail;

    /** KeyTool GUI Mailing List menu item of Online Resources menu */
    private JMenuItem m_jmiMailList;

    /** Check for Update menu item of Online Resources menu */
    private JMenuItem m_jmiCheckUpdate;

    /** Donation menu item of Online Resources menu */
    private JMenuItem m_jmiDonate;

    /** Security Providers menu item of Help menu */
    private JMenuItem m_jmiSecurityProviders;

    /** JARs menu item of Help menu */
    private JMenuItem m_jmiJars;

    /** About menu item of Help menu */
    private JMenuItem m_jmiAbout;

    ////////////////////////////////////////////////////////////
    // Toolbar controls
    ////////////////////////////////////////////////////////////

    /** The Toolbar */
    private JToolBar m_jtbToolBar;

    /** New KeyStore toolbar button */
    private JButton m_jbNewKeyStore;

    /** Open KeyStore toolbar button */
    private JButton m_jbOpenKeyStore;

    /** Save KeyStore toolbar button */
    private JButton m_jbSaveKeyStore;

    /** Generate KeyPair toolbar button */
    private JButton m_jbGenKeyPair;

    /** Import Trusted Certificate toolbar button */
    private JButton m_jbImportTrustCert;

    /** Import KeyPair toolbar button */
    private JButton m_jbImportKeyPair;

    /** Set KeyStore Password toolbar button */
    private JButton m_jbSetKeyStorePass;

    /** Set KeyStore Report toolbar button */
    private JButton m_jbKeyStoreReport;

    /** Examine Certificate toolbar button */
    private JButton m_jbExamineCert;

    /** Examine CRL toolbar button */
    private JButton m_jbExamineCrl;

    /** Donate toolbar button */
    private JButton m_jbDonate;

    /** Help toolbar button */
    private JButton m_jbHelp;

    ////////////////////////////////////////////////////////////
    // Pop-up menu controls
    ////////////////////////////////////////////////////////////

    /** Key Pair entry pop-up menu */
    private JPopupMenu m_jpmKeyPair;

    /** Certificate details menu item of Key Pair entry pop-up menu */
    private JMenuItem m_jmiKeyPairCertDetails;

    /** Export Key Pair entry menu item pop-up menu */
    private JMenuItem m_jmiKeyPairExport;

    /** Generate CSR menu item of Key Pair entry pop-up menu */
    private JMenuItem m_jmiGenerateCSR;

    /** Import menu item of Key Pair entry pop-up menu */
    private JMenuItem m_jmiImportCAReply;

    /** Set Password menu item of Key Pair entry pop-up menu */
    private JMenuItem m_jmiSetKeyPairPass;

    /** Delete menu item of Key Pair entry pop-up menu */
    private JMenuItem m_jmiKeyPairDelete;

    /** Clone menu item of Key Pair entry pop-up menu */
    private JMenuItem m_jmiClone;

    /** Rename menu item of Key Pair entry pop-up menu */
    private JMenuItem m_jmiKeyPairRename;

    /** Trusted Certificate entry pop-up menu */
    private JPopupMenu m_jpmCert;

    /** Details menu item of Trusted Certificate Entry pop-up menu */
    private JMenuItem m_jmiTrustCertDetails;

    /** Export Trusted Certificate entry menu item pop-up menu */
    private JMenuItem m_jmiTrustCertExport;

    /** Export sub-menu binary menu item of Trusted certificate pop-up menu */
    private JMenuItem m_jmiTrustCertExportBin;

    /** Export sub-menu printable menu item of Trusted certificate pop-up menu */
    private JMenuItem m_jmiTrustCertExportPrint;

    /** Delete menu item of Trusted Certificate Entry pop-up menu */
    private JMenuItem m_jmiTrustCertDelete;

    /** Rename menu item of Trusted Certificate entry pop-up menu */
    private JMenuItem m_jmiTrustCertRename;

    ////////////////////////////////////////////////////////////
    // KeyStore table controls
    ////////////////////////////////////////////////////////////

    /** Panel to hold KeyStore entries table */
    private JPanel m_jpKeyStoreTable;

    /** KeyStore entries table */
    private JTable m_jtKeyStore;

    /** Scroll Pane to view KeyStore entries table */
    private JScrollPane m_jspKeyStoreTable;

    ////////////////////////////////////////////////////////////
    // Status bar controls
    ////////////////////////////////////////////////////////////

    /** Label to display current application status messages */
    private JLabel m_jlStatusBar;

    ////////////////////////////////////////////////////////////
    // Actions - these are shared between the menu and toolbar
    ////////////////////////////////////////////////////////////

    /** New KeyStore action */
    private final NewKeyStoreAction m_newKeyStoreAction = new NewKeyStoreAction();

    /** Open KeyStore action */
    private final OpenKeyStoreAction m_openKeyStoreAction = new OpenKeyStoreAction();

    /** Save KeyStore action */
    private final SaveKeyStoreAction m_saveKeyStoreAction = new SaveKeyStoreAction();

    /** Examine Certificate action */
    private final ExamineCertAction m_examineCertAction = new ExamineCertAction();

    /** Examine CRL action */
    private final ExamineCrlAction m_examineCrlAction = new ExamineCrlAction();

    /** Generate KeyPair action */
    private final GenKeyPairAction m_genKeyPairAction = new GenKeyPairAction();

    /** Import Trusted Certificate action */
    private final ImportTrustCertAction m_importTrustCertAction = new ImportTrustCertAction();

    /** Import KeyPair action */
    private final ImportKeyPairAction m_importKeyPairAction = new ImportKeyPairAction();

    /** Set KeyStore Password action */
    private final SetKeyStorePassAction m_setKeyStorePassAction = new SetKeyStorePassAction();

    /** KeyStore Report action */
    private final KeyStoreReportAction m_keyStoreReportAction = new KeyStoreReportAction();

    /** Donate action */
    private final DonateAction m_donateAction = new DonateAction();

    /** Help action */
    private final HelpAction m_helpAction = new HelpAction();

    /**
     * Creates a new FKeyToolGUI frame.
     *
     * @param appProps Application properties
     */
    public FKeyToolGUI(Properties appProps)
    {
        // Get and store non-GUI related application properties
        m_bUseCaCerts = new Boolean(appProps.getProperty(m_res.getString("AppProps.Property.UseCaCerts"))).booleanValue();
        m_fCaCertsFile = new File(appProps.getProperty(m_res.getString("AppProps.Property.CaCertsFile")));

        // Initialise GUI components
        initComponents(appProps);
    }

    /**
     * Initialise FKeyToolGUI frame's GUI components.
     *
     * @param appProps Application properties
     */
    private void initComponents(Properties appProps)
    {
        // Initialise the application's status bar
        initStatusBar();

        // Initialise the application's menu
        initMenu(appProps);

        // Initialise the application's toolbar
        initToolBar();

        // Initialise the application's pop-up menus
        initPopupMenus();

        // Initialise the application's KeyStore table
        initTable(appProps);

        // Handle application close
        addWindowListener(new WindowAdapter()
        {
            public void windowClosing(WindowEvent evt)
            {
                exitApplication();
            }
        });
        setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);

        updateTitle();
        pack();

        /* Set application position according to application properties unless the
           relevant properties are not present or are invalid */
        int iXPos = 0;
        int iYPos = 0;
        try
        {
            iXPos = Integer.parseInt(appProps.getProperty(m_res.getString("AppProps.Property.XPos"), "0"));
            iYPos = Integer.parseInt(appProps.getProperty(m_res.getString("AppProps.Property.YPos"), "0"));
        }
        catch (NumberFormatException nfex) { /* We can safely ignore this */ }

        if ((iXPos <= 0) || (iYPos <= 0))
        {
            // Centre the frame in the centre of the desktop
            setLocationRelativeTo(null);
        }
        else
        {
            // Use application property values for positioning
            setLocation(new Point(iXPos, iYPos));
        }

        // If frame is not completely visible then set it to default size and centre it
        if (!SwingUtilities.isRectangleContainingRectangle(new Rectangle(Toolkit.getDefaultToolkit().getScreenSize()), getBounds()))
        {
            m_jpKeyStoreTable.setPreferredSize(new Dimension(DEFAULT_TABLE_WIDTH, DEFAULT_TABLE_HEIGHT));
            setLocationRelativeTo(null);
        }

        // Set its icon
        setIconImage(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.Icon.image"))));
    }

    /**
     * Initialise FKeyToolGUI frame's main menu GUI components.
     *
     * @param appProps Application properties
     */
    private void initMenu(Properties appProps)
    {
        // The menu items that carry out the same function as toolbar buttons use actions

        // The menu bar
        m_jmbMenuBar = new JMenuBar();

        // File menu
        m_jmrfFile = new JMenuRecentFiles(m_res.getString("FKeyToolGUI.m_jmrfFile.text"), RECENT_FILES_LENGTH, RECENT_FILES_INDEX);
        m_jmrfFile.setMnemonic(m_res.getString("FKeyToolGUI.m_jmrfFile.mnemonic").charAt(0));

        m_jmiNewKeyStore = new JMenuItem(m_newKeyStoreAction);
        m_jmiNewKeyStore.setToolTipText(null);
        new StatusBarChangeHandler(m_jmiNewKeyStore, (String)m_newKeyStoreAction.getValue(Action.LONG_DESCRIPTION), this);
        m_jmrfFile.add(m_jmiNewKeyStore);

        m_jmiOpenKeyStore = new JMenuItem(m_openKeyStoreAction);
        m_jmiOpenKeyStore.setToolTipText(null);
        new StatusBarChangeHandler(m_jmiOpenKeyStore, (String)m_openKeyStoreAction.getValue(Action.LONG_DESCRIPTION), this);
        m_jmrfFile.add(m_jmiOpenKeyStore);

        m_jmrfFile.addSeparator();

        m_jmiSaveKeyStore = new JMenuItem(m_saveKeyStoreAction);
        m_jmiSaveKeyStore.setToolTipText(null);
        new StatusBarChangeHandler(m_jmiSaveKeyStore, (String)m_saveKeyStoreAction.getValue(Action.LONG_DESCRIPTION), this);
        m_jmrfFile.add(m_jmiSaveKeyStore);

        m_jmiSaveKeyStoreAs = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiSaveKeyStoreAs.text"),
                                            m_res.getString("FKeyToolGUI.m_jmiSaveKeyStoreAs.mnemonic").charAt(0));
        m_jmiSaveKeyStoreAs.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiSaveKeyStoreAs.image")))));
        m_jmiSaveKeyStoreAs.setEnabled(false);
        m_jmrfFile.add(m_jmiSaveKeyStoreAs);
        m_jmiSaveKeyStoreAs.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { saveKeyStoreAs(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiSaveKeyStoreAs, m_res.getString("FKeyToolGUI.m_jmiSaveKeyStoreAs.statusbar"), this);

        m_jmrfFile.addSeparator();

        // Add recent files to file menu
        for (int iCnt = RECENT_FILES_LENGTH; iCnt > 0; iCnt--)
        {
            String sRecentFile = appProps.getProperty(m_res.getString("AppProps.Property.RecentFile") + iCnt);

            if (sRecentFile != null)
            {
                m_jmrfFile.add(createRecentFileMenuItem(new File(sRecentFile)));
            }
        }

        m_jmiExit = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiExit.text"),
                                                  m_res.getString("FKeyToolGUI.m_jmiExit.mnemonic").charAt(0));
        m_jmiExit.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiExit.image")))));
        m_jmrfFile.add(m_jmiExit);
        m_jmiExit.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { exitApplication(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiExit, m_res.getString("FKeyToolGUI.m_jmiExit.statusbar"), this);

        // Tools menu
        m_jmTools = new JMenu(m_res.getString("FKeyToolGUI.m_jmTools.text"));
        m_jmTools.setMnemonic(m_res.getString("FKeyToolGUI.m_jmTools.mnemonic").charAt(0));

        m_jmiGenKeyPair = new JMenuItem(m_genKeyPairAction);
        m_jmiGenKeyPair.setToolTipText(null);
        new StatusBarChangeHandler(m_jmiGenKeyPair, (String)m_genKeyPairAction.getValue(Action.LONG_DESCRIPTION), this);
        m_jmTools.add(m_jmiGenKeyPair);

        m_jmiImportTrustCert = new JMenuItem(m_importTrustCertAction);
        m_jmiImportTrustCert.setToolTipText(null);
        new StatusBarChangeHandler(m_jmiImportTrustCert, (String)m_importTrustCertAction.getValue(Action.LONG_DESCRIPTION), this);
        m_jmTools.add(m_jmiImportTrustCert);

        m_jmiImportKeyPair = new JMenuItem(m_importKeyPairAction);
        m_jmiImportKeyPair.setToolTipText(null);
        new StatusBarChangeHandler(m_jmiImportKeyPair, (String)m_importKeyPairAction.getValue(Action.LONG_DESCRIPTION), this);
        m_jmTools.add(m_jmiImportKeyPair);

        m_jmTools.addSeparator();

        m_jmiSetKeyStorePass = new JMenuItem(m_setKeyStorePassAction);
        m_jmiSetKeyStorePass.setToolTipText(null);
        new StatusBarChangeHandler(m_jmiSetKeyStorePass, (String)m_setKeyStorePassAction.getValue(Action.LONG_DESCRIPTION), this);
        m_jmTools.add(m_jmiSetKeyStorePass);

        m_jmChangeKeyStoreType = new JMenu(m_res.getString("FKeyToolGUI.m_jmChangeKeyStoreType.text"));
        m_jmChangeKeyStoreType.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmChangeKeyStoreType.image")))));
        m_jmChangeKeyStoreType.setMnemonic(m_res.getString("FKeyToolGUI.m_jmChangeKeyStoreType.mnemonic").charAt(0));
        m_jmChangeKeyStoreType.setEnabled(false);
        m_jmTools.add(m_jmChangeKeyStoreType);

        // Add Change KeyStore Type sub-menu of Tools
        m_jmiChangeKeyStoreTypeJks = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiChangeKeyStoreTypeJks.text"),
                                                   m_res.getString("FKeyToolGUI.m_jmiChangeKeyStoreTypeJks.mnemonic").charAt(0));
        m_jmiChangeKeyStoreTypeJks.setEnabled(false);
        m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeJks);
        m_jmiChangeKeyStoreTypeJks.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { changeKeyStoreType(KeyStoreType.JKS); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiChangeKeyStoreTypeJks, m_res.getString("FKeyToolGUI.m_jmiChangeKeyStoreTypeJks.statusbar"), this);

        m_jmiChangeKeyStoreTypeJceks = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiChangeKeyStoreTypeJceks.text"),
                                                     m_res.getString("FKeyToolGUI.m_jmiChangeKeyStoreTypeJceks.mnemonic").charAt(0));
        m_jmiChangeKeyStoreTypeJceks.setEnabled(false);
        m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeJceks);
        m_jmiChangeKeyStoreTypeJceks.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { changeKeyStoreType(KeyStoreType.JCEKS); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiChangeKeyStoreTypeJceks, m_res.getString("FKeyToolGUI.m_jmiChangeKeyStoreTypeJceks.statusbar"), this);

        m_jmiChangeKeyStoreTypePkcs12 = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiChangeKeyStoreTypePkcs12.text"),
                                                      m_res.getString("FKeyToolGUI.m_jmiChangeKeyStoreTypePkcs12.mnemonic").charAt(0));
        m_jmiChangeKeyStoreTypePkcs12.setEnabled(false);
        m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypePkcs12);
        m_jmiChangeKeyStoreTypePkcs12.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { changeKeyStoreType(KeyStoreType.PKCS12); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiChangeKeyStoreTypePkcs12, m_res.getString("FKeyToolGUI.m_jmiChangeKeyStoreTypePkcs12.statusbar"), this);

        m_jmiChangeKeyStoreTypeBks = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiChangeKeyStoreTypeBks.text"),
                                                   m_res.getString("FKeyToolGUI.m_jmiChangeKeyStoreTypeBks.mnemonic").charAt(0));
        m_jmiChangeKeyStoreTypeBks.setEnabled(false);
        m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeBks);
        m_jmiChangeKeyStoreTypeBks.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { changeKeyStoreType(KeyStoreType.BKS); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiChangeKeyStoreTypeBks, m_res.getString("FKeyToolGUI.m_jmiChangeKeyStoreTypeBks.statusbar"), this);

        m_jmiChangeKeyStoreTypeUber = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiChangeKeyStoreTypeUber.text"),
                                                    m_res.getString("FKeyToolGUI.m_jmiChangeKeyStoreTypeUber.mnemonic").charAt(0));
        m_jmiChangeKeyStoreTypeUber.setEnabled(false);
        m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeUber);
        m_jmiChangeKeyStoreTypeUber.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { changeKeyStoreType(KeyStoreType.UBER); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiChangeKeyStoreTypeUber, m_res.getString("FKeyToolGUI.m_jmiChangeKeyStoreTypeUber.statusbar"), this);

        m_jmiKeyStoreReport = new JMenuItem(m_keyStoreReportAction);
        m_jmiKeyStoreReport.setToolTipText(null);
        new StatusBarChangeHandler(m_jmiKeyStoreReport, (String)m_keyStoreReportAction.getValue(Action.LONG_DESCRIPTION), this);
        m_jmTools.add(m_jmiKeyStoreReport);

        m_jmTools.addSeparator();

        m_jmiOptions = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiOptions.text"),
                                     m_res.getString("FKeyToolGUI.m_jmiOptions.mnemonic").charAt(0));
        m_jmiOptions.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiOptions.image")))));
        m_jmTools.add(m_jmiOptions);
        m_jmiOptions.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { showOptions(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiOptions, m_res.getString("FKeyToolGUI.m_jmiOptions.statusbar"), this);

        // Examine menu
        m_jmExamine = new JMenu(m_res.getString("FKeyToolGUI.m_jmExamine.text"));
        m_jmExamine.setMnemonic(m_res.getString("FKeyToolGUI.m_jmExamine.mnemonic").charAt(0));

        m_jmiExamineCert = new JMenuItem(m_examineCertAction);
        m_jmiExamineCert.setToolTipText(null);
        new StatusBarChangeHandler(m_jmiExamineCert, (String)m_examineCertAction.getValue(Action.LONG_DESCRIPTION), this);
        m_jmExamine.add(m_jmiExamineCert);

        m_jmiExamineCrl = new JMenuItem(m_examineCrlAction);
        m_jmiExamineCrl.setToolTipText(null);
        new StatusBarChangeHandler(m_jmiExamineCrl, (String)m_examineCrlAction.getValue(Action.LONG_DESCRIPTION), this);
        m_jmExamine.add(m_jmiExamineCrl);

        // Help menu
        m_jmHelp = new JMenu(m_res.getString("FKeyToolGUI.m_jmHelp.text"));
        m_jmHelp.setMnemonic(m_res.getString("FKeyToolGUI.m_jmHelp.mnemonic").charAt(0));

        m_jmiHelp = new JMenuItem(m_helpAction);
        m_jmiHelp.setToolTipText(null);
        new StatusBarChangeHandler(m_jmiHelp, (String)m_helpAction.getValue(Action.LONG_DESCRIPTION), this);
        m_jmHelp.add(m_jmiHelp);

        // Online Resources menu (sub-menu of Help)
        m_jmOnlineResources = new JMenu(m_res.getString("FKeyToolGUI.m_jmOnlineResources.text"));
        m_jmOnlineResources.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmOnlineResources.image")))));
        m_jmOnlineResources.setMnemonic(m_res.getString("FKeyToolGUI.m_jmOnlineResources.mnemonic").charAt(0));
        m_jmHelp.add(m_jmOnlineResources);

        m_jmiWebsite = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiWebsite.text"),
                                     m_res.getString("FKeyToolGUI.m_jmiWebsite.mnemonic").charAt(0));
        m_jmiWebsite.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiWebsite.image")))));
        m_jmOnlineResources.add(m_jmiWebsite);
        m_jmiWebsite.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { visitWebsite(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiWebsite, m_res.getString("FKeyToolGUI.m_jmiWebsite.statusbar"), this);

        m_jmiSFNetProject = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiSFNetProject.text"),
                                          m_res.getString("FKeyToolGUI.m_jmiSFNetProject.mnemonic").charAt(0));
        m_jmiSFNetProject.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiSFNetProject.image")))));
        m_jmOnlineResources.add(m_jmiSFNetProject);
        m_jmiSFNetProject.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { visitSFNetProject(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiSFNetProject, m_res.getString("FKeyToolGUI.m_jmiSFNetProject.statusbar"), this);

        m_jmiEmail = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiEmail.text"),
                                   m_res.getString("FKeyToolGUI.m_jmiEmail.mnemonic").charAt(0));
        m_jmiEmail.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiEmail.image")))));
        m_jmOnlineResources.add(m_jmiEmail);
        m_jmiEmail.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { composeEmail(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiEmail, m_res.getString("FKeyToolGUI.m_jmiEmail.statusbar"), this);

        m_jmiMailList = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiMailList.text"),
                                   m_res.getString("FKeyToolGUI.m_jmiMailList.mnemonic").charAt(0));
        m_jmiMailList.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiMailList.image")))));
        m_jmOnlineResources.add(m_jmiMailList);
        m_jmiMailList.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { visitMailListSignup(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiMailList, m_res.getString("FKeyToolGUI.m_jmiMailList.statusbar"), this);

        m_jmiCheckUpdate = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiCheckUpdate.text"),
                                         m_res.getString("FKeyToolGUI.m_jmiCheckUpdate.mnemonic").charAt(0));
        m_jmiCheckUpdate.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiCheckUpdate.image")))));
        m_jmOnlineResources.add(m_jmiCheckUpdate);
        m_jmiCheckUpdate.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { checkForUpdate(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiCheckUpdate, m_res.getString("FKeyToolGUI.m_jmiCheckUpdate.statusbar"), this);

        m_jmiDonate = new JMenuItem(m_donateAction);
        m_jmiDonate.setToolTipText(null);
        new StatusBarChangeHandler(m_jmiDonate, (String)m_donateAction.getValue(Action.LONG_DESCRIPTION), this);
        m_jmHelp.add(m_jmiDonate);

        m_jmHelp.addSeparator();

        m_jmiSecurityProviders = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiSecurityProviders.text"),
                                               m_res.getString("FKeyToolGUI.m_jmiSecurityProviders.mnemonic").charAt(0));
        m_jmiSecurityProviders.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiSecurityProviders.image")))));
        m_jmHelp.add(m_jmiSecurityProviders);
        m_jmiSecurityProviders.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { showSecurityProviders(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiSecurityProviders, m_res.getString("FKeyToolGUI.m_jmiSecurityProviders.statusbar"), this);

        m_jmiJars = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiJars.text"),
                                                  m_res.getString("FKeyToolGUI.m_jmiJars.mnemonic").charAt(0));
        m_jmiJars.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiJars.image")))));
        m_jmHelp.add(m_jmiJars);
        m_jmiJars.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { showJarInfo(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiJars, m_res.getString("FKeyToolGUI.m_jmiJars.statusbar"), this);

        m_jmHelp.addSeparator();

        m_jmiAbout = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiAbout.text"),
                                   m_res.getString("FKeyToolGUI.m_jmiAbout.mnemonic").charAt(0));
        m_jmiAbout.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiAbout.image")))));
        m_jmHelp.add(m_jmiAbout);
        m_jmiAbout.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { showAbout(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiAbout, m_res.getString("FKeyToolGUI.m_jmiAbout.statusbar"), this);

        // Add the menus to the menu bar
        m_jmbMenuBar.add(m_jmrfFile);
        m_jmbMenuBar.add(m_jmTools);
        m_jmbMenuBar.add(m_jmExamine);
        m_jmbMenuBar.add(m_jmHelp);

        // Add menu bar to application frame
        setJMenuBar(m_jmbMenuBar);
    }

    /**
     * Create a recent file menu item for the supplied file.
     *
     * @param fRecentFile Recent file
     * @return Recent file menu item
     */
    private JMenuItemRecentFile createRecentFileMenuItem(File fRecentFile)
    {
        JMenuItemRecentFile jmirfNew = new JMenuItemRecentFile(fRecentFile);
        jmirfNew.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.OpenRecent.image")))));
        jmirfNew.addActionListener(new RecentKeyStoreFileActionListener(fRecentFile, this));

        new StatusBarChangeHandler(jmirfNew, MessageFormat.format(m_res.getString("FKeyToolGUI.recentfile.statusbar"), new Object[]{fRecentFile}), this);
        return jmirfNew;
    }

    /**
     * Initialise FKeyToolGUI frame's toolbar GUI components.
     */
    private void initToolBar()
    {
        // Create the "new" toolbar button
        m_jbNewKeyStore = new JButton();
        m_jbNewKeyStore.setAction(m_newKeyStoreAction);
        m_jbNewKeyStore.setText(null); // Don't share text from action
        m_jbNewKeyStore.setMnemonic(0); // Get around bug with action mnemonics on toolbar buttons
        m_jbNewKeyStore.setFocusable(false);
        m_jbNewKeyStore.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String)m_newKeyStoreAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "open" toolbar button
        m_jbOpenKeyStore = new JButton();
        m_jbOpenKeyStore.setAction(m_openKeyStoreAction);
        m_jbOpenKeyStore.setText(null); // Don't share text from action
        m_jbOpenKeyStore.setMnemonic(0); // Get around bug with action mnemonics on toolbar buttons
        m_jbOpenKeyStore.setFocusable(false);
        m_jbOpenKeyStore.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String)m_openKeyStoreAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "save" toolbar button
        m_jbSaveKeyStore = new JButton();
        m_jbSaveKeyStore.setAction(m_saveKeyStoreAction);
        m_jbSaveKeyStore.setText(null); // Don't share text from action
        m_jbSaveKeyStore.setMnemonic(0); // Get around bug with action mnemonics on toolbar buttons
        m_jbSaveKeyStore.setFocusable(false);
        m_jbSaveKeyStore.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String)m_saveKeyStoreAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "generate keypair" toolbar button
        m_jbGenKeyPair = new JButton();
        m_jbGenKeyPair.setAction(m_genKeyPairAction);
        m_jbGenKeyPair.setText(null); // Don't share text from action
        m_jbGenKeyPair.setMnemonic(0); // Get around bug with action mnemonics on toolbar buttons
        m_jbGenKeyPair.setFocusable(false);
        m_jbGenKeyPair.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String)m_genKeyPairAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "import trusted certificate" toolbar button
        m_jbImportTrustCert = new JButton();
        m_jbImportTrustCert.setAction(m_importTrustCertAction);
        m_jbImportTrustCert.setText(null); // Don't share text from action
        m_jbImportTrustCert.setMnemonic(0); // Get around bug with action mnemonics on toolbar buttons
        m_jbImportTrustCert.setFocusable(false);
        m_jbImportTrustCert.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String)m_importTrustCertAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "import key pair" toolbar button
        m_jbImportKeyPair = new JButton();
        m_jbImportKeyPair.setAction(m_importKeyPairAction);
        m_jbImportKeyPair.setText(null); // Don't share text from action
        m_jbImportKeyPair.setMnemonic(0); // Get around bug with action mnemonics on toolbar buttons
        m_jbImportKeyPair.setFocusable(false);
        m_jbImportKeyPair.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String)m_importKeyPairAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "set keystore password" toolbar button
        m_jbSetKeyStorePass = new JButton();
        m_jbSetKeyStorePass.setAction(m_setKeyStorePassAction);
        m_jbSetKeyStorePass.setText(null); // Don't share text from action
        m_jbSetKeyStorePass.setMnemonic(0); // Get around bug with action mnemonics on toolbar buttons
        m_jbSetKeyStorePass.setFocusable(false);
        m_jbSetKeyStorePass.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String)m_setKeyStorePassAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "keystore report" toolbar button
        m_jbKeyStoreReport = new JButton();
        m_jbKeyStoreReport.setAction(m_keyStoreReportAction);
        m_jbKeyStoreReport.setText(null); // Don't share text from action
        m_jbKeyStoreReport.setMnemonic(0); // Get around bug with action mnemonics on toolbar buttons
        m_jbKeyStoreReport.setFocusable(false);
        m_jbKeyStoreReport.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String)m_keyStoreReportAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "examine certificate" toolbar button
        m_jbExamineCert = new JButton();
        m_jbExamineCert.setAction(m_examineCertAction);
        m_jbExamineCert.setText(null); // Don't share text from action
        m_jbExamineCert.setMnemonic(0); // Get around bug with action mnemonics on toolbar buttons
        m_jbExamineCert.setFocusable(false);
        m_jbExamineCert.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String)m_examineCertAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "examine crl" toolbar button
        m_jbExamineCrl = new JButton();
        m_jbExamineCrl.setAction(m_examineCrlAction);
        m_jbExamineCrl.setText(null); // Don't share text from action
        m_jbExamineCrl.setMnemonic(0); // Get around bug with action mnemonics on toolbar buttons
        m_jbExamineCrl.setFocusable(false);
        m_jbExamineCrl.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String)m_examineCrlAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "help" toolbar button
        m_jbDonate = new JButton();
        m_jbDonate.setAction(m_donateAction);
        m_jbDonate.setText(null); // Don't share text from action
        m_jbDonate.setMnemonic(0); // Get around bug with action mnemonics on toolbar buttons
        m_jbDonate.setFocusable(false);
        m_jbDonate.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String)m_donateAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "help" toolbar button
        m_jbHelp = new JButton();
        m_jbHelp.setAction(m_helpAction);
        m_jbHelp.setText(null); // Don't share text from action
        m_jbHelp.setMnemonic(0); // Get around bug with action mnemonics on toolbar buttons
        m_jbHelp.setFocusable(false);
        m_jbHelp.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String)m_helpAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // The toolbar
        m_jtbToolBar = new JToolBar();
        m_jtbToolBar.setFloatable(false);
        m_jtbToolBar.setRollover(true);
        m_jtbToolBar.setName(m_res.getString("FKeyToolGUI.m_jtbToolBar.name"));

        // Add the buttons to the toolbar - use visible separators for all L&Fs
        m_jtbToolBar.add(m_jbNewKeyStore);
        m_jtbToolBar.add(m_jbOpenKeyStore);
        m_jtbToolBar.add(m_jbSaveKeyStore);

        JSeparator separator1 = new JSeparator(SwingConstants.VERTICAL);
        separator1.setMaximumSize(new Dimension(3, 16));
        m_jtbToolBar.add(separator1);

        m_jtbToolBar.add(m_jbGenKeyPair);
        m_jtbToolBar.add(m_jbImportTrustCert);
        m_jtbToolBar.add(m_jbImportKeyPair);
        m_jtbToolBar.add(m_jbSetKeyStorePass);
        m_jtbToolBar.add(m_jbKeyStoreReport);

        JSeparator separator2 = new JSeparator(SwingConstants.VERTICAL);
        separator2.setMaximumSize(new Dimension(3, 16));
        m_jtbToolBar.add(separator2);

        m_jtbToolBar.add(m_jbExamineCert);
        m_jtbToolBar.add(m_jbExamineCrl);

        JSeparator separator3 = new JSeparator(SwingConstants.VERTICAL);
        separator3.setMaximumSize(new Dimension(3, 16));
        m_jtbToolBar.add(separator3);

        m_jtbToolBar.add(m_jbDonate);
        m_jtbToolBar.add(m_jbHelp);

        // Add the toolbar to the frame
        getContentPane().add(m_jtbToolBar, BorderLayout.NORTH);
    }

    /**
     * Initialise FKeyToolGUI frame's KeyStore content table GUI components.
     *
     * @param appProps Application properties
     */
    private void initTable(Properties appProps)
    {
        // The table data model
        KeyStoreTableModel ksModel = new KeyStoreTableModel();

        // The table itself
        m_jtKeyStore = new JTable(ksModel);

        m_jtKeyStore.setShowGrid(false);
        m_jtKeyStore.setRowMargin(0);
        m_jtKeyStore.getColumnModel().setColumnMargin(0);
        m_jtKeyStore.getTableHeader().setReorderingAllowed(false);
        m_jtKeyStore.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        m_jtKeyStore.setRowHeight(18); // Top accomodate entry icons with spare space (they are 16 pixels tall)

        // Add custom renderers for the table headers and cells
        for (int iCnt=0; iCnt < m_jtKeyStore.getColumnCount(); iCnt++)
        {
            TableColumn column =  m_jtKeyStore.getColumnModel().getColumn(iCnt);
            column.setHeaderRenderer(new KeyStoreTableHeadRend());
            column.setCellRenderer(new KeyStoreTableCellRend());
        }

        /* Make the first column small and not resizable (it holds icons to
           represent the different entry types) */
        TableColumn typeCol = m_jtKeyStore.getColumnModel().getColumn(0);
        typeCol.setResizable(false);
        typeCol.setMinWidth(20);
        typeCol.setMaxWidth(20);
        typeCol.setPreferredWidth(20);

        /* Set alias columns width according to the relevant application property
           unless the property is not present or is invalid */
        int iAliasWidth = 0;
        try
        {
            iAliasWidth = Integer.parseInt(appProps.getProperty(m_res.getString("AppProps.Property.AliasWidth"), "0"));
        }
        catch (NumberFormatException nfex) { /* We can safely ignore this */ }

        TableColumn aliasCol = m_jtKeyStore.getColumnModel().getColumn(1);
        aliasCol.setMinWidth(20);
        aliasCol.setMaxWidth(10000);

        if (iAliasWidth <= 0)
        {
            aliasCol.setPreferredWidth(350);
        }
        else
        {
            aliasCol.setPreferredWidth(iAliasWidth);
        }

        // Put the table into a scroll pane
        m_jspKeyStoreTable = new JScrollPane(m_jtKeyStore,
                                             JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                                             JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        m_jspKeyStoreTable.getViewport().setBackground(m_jtKeyStore.getBackground());

        // Get the size of the KeyStore table panel from the application properties
        int iWidth = 0;
        int iHeight = 0;
        try
        {
            iWidth = Integer.parseInt(appProps.getProperty(m_res.getString("AppProps.Property.TableWidth")));
            iHeight = Integer.parseInt(appProps.getProperty(m_res.getString("AppProps.Property.TableHeight")));
        }
        catch (NumberFormatException nfex) { /* We can safely ignore this */ }

        // Put the scroll pane into a panel.  The preferred size of the panel
        // dictates the size of the entire frame
        m_jpKeyStoreTable = new JPanel(new BorderLayout(10, 10));

        if ((iWidth <= 0) || (iHeight <= 0))
        {
            m_jpKeyStoreTable.setPreferredSize(new Dimension(DEFAULT_TABLE_WIDTH, DEFAULT_TABLE_HEIGHT));
        }
        else
        {
            m_jpKeyStoreTable.setPreferredSize(new Dimension(iWidth, iHeight));
        }

        m_jpKeyStoreTable.add(m_jspKeyStoreTable, BorderLayout.CENTER);
		m_jpKeyStoreTable.setBorder(new EmptyBorder(3, 3, 3, 3));

        /* Add mouse listeners to show pop-up menus when table entries are
           clicked upon - maybeShowPopup for both mousePressed and mouseReleased
           for cross-platform compatibility.  Also add listeners to show an
           entry's certificate details if it is double-clicked */
        m_jtKeyStore.addMouseListener(new MouseAdapter()
        {
            public void mouseClicked(MouseEvent evt)
            {
                keyStoreTableDoubleClick(evt);
            }

            public void mousePressed(MouseEvent evt)
            {
                maybeShowPopup(evt);
            }

            public void mouseReleased(MouseEvent evt)
            {
                maybeShowPopup(evt);
            }
        });

        getContentPane().add(m_jpKeyStoreTable, BorderLayout.CENTER);
    }

    /**
     * Initialise FKeyToolGUI frame's status bar GUI components.
     */
    private void initStatusBar()
    {
        m_jlStatusBar = new JLabel();

        m_jlStatusBar.setBorder(new CompoundBorder(new EmptyBorder(3, 3, 3, 3),
                                                   new CompoundBorder(new BevelBorder(BevelBorder.LOWERED),
                                                                      new EmptyBorder(0, 2, 0, 2))));
        setDefaultStatusBarText();

        getContentPane().add(m_jlStatusBar, BorderLayout.SOUTH);
    }

    /**
     * Initialise FKeyToolGUI frame's popup menu GUI components.  These are invoked
     * when rows of specific types are clicked upon in the KeyStore table.
     */
    private void initPopupMenus()
    {
        // Initialiase Key Pair entry pop-up menu including mnemonics and listeners
        m_jpmKeyPair = new JPopupMenu();

        m_jmiKeyPairCertDetails = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiKeyPairCertDetails.text"),
                                                m_res.getString("FKeyToolGUI.m_jmiKeyPairCertDetails.mnemonic").charAt(0));
        m_jmiKeyPairCertDetails.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiKeyPairCertDetails.image")))));
        m_jmiKeyPairCertDetails.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { showSelectedEntry(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiKeyPairCertDetails, m_res.getString("FKeyToolGUI.m_jmiKeyPairCertDetails.statusbar"), this);

        m_jmiKeyPairExport = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiKeyPairExport.text"),
                                           m_res.getString("FKeyToolGUI.m_jmiKeyPairExport.mnemonic").charAt(0));
        m_jmiKeyPairExport.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiKeyPairExport.image")))));

        m_jmiKeyPairExport.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { exportSelectedEntry(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiKeyPairExport, m_res.getString("FKeyToolGUI.m_jmiKeyPairExport.statusbar"), this);


        m_jmiGenerateCSR = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiGenerateCSR.text"),
                                         m_res.getString("FKeyToolGUI.m_jmiGenerateCSR.mnemonic").charAt(0));
        m_jmiGenerateCSR.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiGenerateCSR.image")))));
        m_jmiGenerateCSR.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { generateCsrSelectedEntry(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiGenerateCSR, m_res.getString("FKeyToolGUI.m_jmiGenerateCSR.statusbar"), this);

        m_jmiImportCAReply = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiImportCAReply.text"),
                                           m_res.getString("FKeyToolGUI.m_jmiImportCAReply.mnemonic").charAt(0));
        m_jmiImportCAReply.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiImportCAReply.image")))));
        m_jmiImportCAReply.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { importCAReplySelectedEntry(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiImportCAReply, m_res.getString("FKeyToolGUI.m_jmiImportCAReply.statusbar"), this);

        m_jmiSetKeyPairPass = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiSetKeyPairPass.text"),
                                        m_res.getString("FKeyToolGUI.m_jmiSetKeyPairPass.mnemonic").charAt(0));
        m_jmiSetKeyPairPass.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiSetKeyPairPass.image")))));
        m_jmiSetKeyPairPass.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { setPasswordSelectedEntry(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiSetKeyPairPass, m_res.getString("FKeyToolGUI.m_jmiSetKeyPairPass.statusbar"), this);

        m_jmiKeyPairDelete = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiKeyPairDelete.text"),
                                           m_res.getString("FKeyToolGUI.m_jmiKeyPairDelete.mnemonic").charAt(0));
        m_jmiKeyPairDelete.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiKeyPairDelete.image")))));
        m_jmiKeyPairDelete.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { deleteSelectedEntry(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiKeyPairDelete, m_res.getString("FKeyToolGUI.m_jmiKeyPairDelete.statusbar"), this);

        m_jmiClone = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiClone.text"),
                                   m_res.getString("FKeyToolGUI.m_jmiClone.mnemonic").charAt(0));
        m_jmiClone.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiClone.image")))));
        m_jmiClone.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { cloneSelectedEntry(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiClone, m_res.getString("FKeyToolGUI.m_jmiClone.statusbar"), this);

        m_jmiKeyPairRename = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiKeyPairRename.text"),
                                           m_res.getString("FKeyToolGUI.m_jmiKeyPairRename.mnemonic").charAt(0));
        m_jmiKeyPairRename.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiKeyPairRename.image")))));
        m_jmiKeyPairRename.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { renameSelectedEntry(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiKeyPairRename, m_res.getString("FKeyToolGUI.m_jmiKeyPairRename.statusbar"), this);

        m_jpmKeyPair.add(m_jmiKeyPairCertDetails);
        m_jpmKeyPair.addSeparator();
        m_jpmKeyPair.add(m_jmiKeyPairExport);
        m_jpmKeyPair.add(m_jmiGenerateCSR);
        m_jpmKeyPair.add(m_jmiImportCAReply);
        m_jpmKeyPair.addSeparator();
        m_jpmKeyPair.add(m_jmiSetKeyPairPass);
        m_jpmKeyPair.add(m_jmiKeyPairDelete);
        m_jpmKeyPair.add(m_jmiClone);
        m_jpmKeyPair.add(m_jmiKeyPairRename);

        // Initialise Trusted Certificate entry pop-up menu including mnemonics and listeners
        m_jpmCert = new JPopupMenu();

        m_jmiTrustCertDetails = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiTrustCertDetails.text"),
                                              m_res.getString("FKeyToolGUI.m_jmiTrustCertDetails.mnemonic").charAt(0));
        m_jmiTrustCertDetails.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiTrustCertDetails.image")))));
        m_jmiTrustCertDetails.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { showSelectedEntry(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiTrustCertDetails, m_res.getString("FKeyToolGUI.m_jmiTrustCertDetails.statusbar"), this);

        m_jmiTrustCertExport = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiTrustCertExport.text"),
                                             m_res.getString("FKeyToolGUI.m_jmTrustCertExport.mnemonic").charAt(0));
        m_jmiTrustCertExport.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiTrustCertExport.image")))));
        m_jmiTrustCertExport.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { exportSelectedEntry(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiTrustCertExport, m_res.getString("FKeyToolGUI.m_jmiTrustCertExport.statusbar"), this);

        m_jmiTrustCertDelete = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiTrustCertDelete.text"),
                                             m_res.getString("FKeyToolGUI.m_jmiTrustCertDelete.mnemonic").charAt(0));
        m_jmiTrustCertDelete.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiTrustCertDelete.image")))));
        m_jmiTrustCertDelete.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { deleteSelectedEntry(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiTrustCertDelete, m_res.getString("FKeyToolGUI.m_jmiTrustCertDelete.statusbar"), this);

        m_jmiTrustCertRename = new JMenuItem(m_res.getString("FKeyToolGUI.m_jmiTrustCertRename.text"),
                                             m_res.getString("FKeyToolGUI.m_jmiTrustCertRename.mnemonic").charAt(0));
        m_jmiTrustCertRename.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.m_jmiTrustCertRename.image")))));
        m_jmiTrustCertRename.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                setDefaultStatusBarText();
                setCursorBusy();
                repaint();

                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try { renameSelectedEntry(); } finally { setCursorFree(); }
                }});
                t.start();
            }
        });
        new StatusBarChangeHandler(m_jmiTrustCertRename, m_res.getString("FKeyToolGUI.m_jmiTrustCertRename.statusbar"), this);

        m_jpmCert.add(m_jmiTrustCertDetails);
        m_jpmCert.addSeparator();
        m_jpmCert.add(m_jmiTrustCertExport);
        m_jpmCert.addSeparator();
        m_jpmCert.add(m_jmiTrustCertDelete);
        m_jpmCert.add(m_jmiTrustCertRename);
    }

    /**
     * Show the appropriate pop-up menu if the originating mouse event indicates
     * that the user clicked upon a KeyStore entry in the UI table and the entry
     * is of type key pair or trusted certificate.
     *
     * @param evt The mouse event
     */
    private void maybeShowPopup(MouseEvent evt)
    {
        if (evt.isPopupTrigger())
        {
            // What row and column were clicked upon (if any)?
            Point point = new Point(evt.getX(), evt.getY());
            int iRow = m_jtKeyStore.rowAtPoint(point);
            int iCol = m_jtKeyStore.columnAtPoint(point);

            if (iRow != -1)
            {
                // Make the row that was clicked upon the selected one
                m_jtKeyStore.setRowSelectionInterval(iRow, iRow);

                // Show one menu if the KeyStore entry is of type key pair...
                if (((String)m_jtKeyStore.getValueAt(iRow, 0)).equals(KeyStoreTableModel.KEY_PAIR_ENTRY))
                {
                    m_jpmKeyPair.show(evt.getComponent(), evt.getX(), evt.getY());
                }
                // ...and another if the type is trusted certificate
                else if (((String)m_jtKeyStore.getValueAt(iRow, 0)).equals(KeyStoreTableModel.TRUST_CERT_ENTRY))
                {
                    m_jpmCert.show(evt.getComponent(), evt.getX(), evt.getY());
                }
            }
        }
    }

    /**
     * Check if a double click occurred on the KeyStore table.  If it has
     * show the certificate details of the entry clicked upon.
     *
     * @param evt The mouse event
     */
    private void keyStoreTableDoubleClick(MouseEvent evt)
    {
        if (evt.getClickCount() > 1)
        {
            // What row and column were clicked upon (if any)?
            Point point = new Point(evt.getX(), evt.getY());
            int iRow = m_jtKeyStore.rowAtPoint(point);

            // Entry clicked upon
            if (iRow != -1)
            {
                // Get the entry type of the row
                KeyStoreTableModel tableModel = (KeyStoreTableModel)m_jtKeyStore.getModel();

                // Make the row that was clicked upon the selected one
                m_jtKeyStore.setRowSelectionInterval(iRow, iRow);

                // Show the selected entry
                showSelectedEntry();
            }
        }
    }

    /**
     * Display the about dialog.
     */
    private void showAbout()
    {
        // Display About Dialog in the centre of the frame
        DAbout dAbout = new DAbout(this, m_res.getString("FKeyToolGUI.About.Title"), true,
        Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.About.image"))));
        dAbout.setLocationRelativeTo(this);
        dAbout.setVisible(true);
    }

    /**
     * Generate a key pair (with certificate) in the currently opened KeyStore.
     *
     * @return True if a key pair is generated, false otherwise
     */
    private boolean generateKeyPair()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // Display the Generate Key Pair dialog to get the key pair generation
        // parameters from the user
        DGenerateKeyPair dGenerateKeyPair = new DGenerateKeyPair(this, true);
        dGenerateKeyPair.setLocationRelativeTo(this);
        dGenerateKeyPair.setVisible(true);

        if (!dGenerateKeyPair.isSuccessful())
        {
            return false; // User cancelled the dialog
        }

        int iKeySize = dGenerateKeyPair.getKeySize();
        KeyPairType keyPairType = dGenerateKeyPair.getKeyPairType();

        // Display the Generating KeyPair dialog - generates the key pair
        DGeneratingKeyPair dGeneratingKeyPair = new DGeneratingKeyPair(this, true, keyPairType, iKeySize);
        dGeneratingKeyPair.setLocationRelativeTo(this);
        dGeneratingKeyPair.startKeyPairGeneration();
        dGeneratingKeyPair.setVisible(true);

        KeyPair keyPair = dGeneratingKeyPair.getKeyPair();

        if (keyPair == null)
        {
            return false; // User cancelled the dialog or error occured
        }

        /* Now display the certificate generation dialog supplying the
           key pair and signature algorithm - this will update the KeyStore
           with the key pair for us */
        DGenerateCertificate dGenerateCertificate =
            new DGenerateCertificate(this, m_res.getString("FKeyToolGUI.GenerateCertificate.Title"), true, keyPair, keyPairType);
        dGenerateCertificate.setLocationRelativeTo(this);
        dGenerateCertificate.setVisible(true);

        X509Certificate certificate = dGenerateCertificate.getCertificate();

        if (certificate == null)
        {
            return false; // user cancelled dialog or error occurred
        }

        // Get the KeyStore
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        // Get an alias for the new KeyStore entry
        String sAlias = null;

        // Get the alias
        DGetAlias dGetAlias = new DGetAlias(this, m_res.getString("DGenerateCertificate.KeyPairEntryAlias.Title"), true, X509CertUtil.getCertificateAlias(certificate));
        dGetAlias.setLocationRelativeTo(this);
        dGetAlias.setVisible(true);
        sAlias = dGetAlias.getAlias();

        if (sAlias == null)
        {
            return false;
        }

        try
        {
            // Check entry does not already exist in the KeyStore
            if (keyStore.containsAlias(sAlias))
            {
                String sMessage = MessageFormat.format(m_res.getString("DGenerateCertificate.OverwriteAlias.message"),
                                                       new String[]{sAlias});

                int iSelected = JOptionPane.showConfirmDialog(this, sMessage, m_res.getString("DGenerateCertificate.KeyPairEntryAlias.Title"),
                                                              JOptionPane.YES_NO_CANCEL_OPTION);
                if (iSelected == JOptionPane.CANCEL_OPTION)
                {
                    return false;
                }
                else if (iSelected == JOptionPane.NO_OPTION)
                {
                    return false;
                }
                // Otherwise carry on - delete entry to be copied over
                keyStore.deleteEntry(sAlias);
            }
        }
        catch (KeyStoreException ex)
        {
            displayException(ex);
            return false;
        }

        // Get a password for the new KeyStore entry (only relevant if the KeyStore is not PKCS #12)
        char[] cPassword = PKCS12_DUMMY_PASSWORD;

        if (!keyStore.getType().equals(KeyStoreType.PKCS12.toString()))
        {
            DGetNewPassword dGetNewPassword = new DGetNewPassword(this, m_res.getString("DGenerateCertificate.KeyPairEntryPassword.Title"), true);
            dGetNewPassword.setLocationRelativeTo(this);
            dGetNewPassword.setVisible(true);
            cPassword = dGetNewPassword.getPassword();

            if (cPassword == null)
            {
                return false;
            }
        }

        // Place the private key and certificate into the KeyStore and update
        // the KeyStore wrapper
        try
        {
            keyStore.setKeyEntry(sAlias, keyPair.getPrivate(), cPassword, new X509Certificate[]{certificate});
            m_keyStoreWrap.setEntryPassword(sAlias, cPassword);
            m_keyStoreWrap.setChanged(true);
        }
        catch (KeyStoreException ex)
        {
            displayException(ex);
            return false;
        }

        // Update the frame's components and title
        updateControls();
        updateTitle();

        // Display success message
        JOptionPane.showMessageDialog(this,
                                      m_res.getString("FKeyToolGUI.KeyPairGenerationSuccessful.message"),
                                      m_res.getString("FKeyToolGUI.GenerateCertificate.Title"),
                                      JOptionPane.INFORMATION_MESSAGE);
        return true;
    }

    /**
     * Open a KeyStore from disk.
     *
     * @return True if a KeyStore is opened, false otherwise
     */
    private boolean openKeyStore()
    {
        // Does the current KeyStore contain unsaved changes?
        if (needSave())
        {
            // Yes - ask the user if it should be saved
            int iWantSave = wantSave();

            if (iWantSave == JOptionPane.YES_OPTION)
            {
                // Save it
                if (!saveKeyStore())
                {
                    return false;
                }
            }
            else if (iWantSave == JOptionPane.CANCEL_OPTION)
            {
                return false;
            }
        }

        // Let the user choose a file to open from
        JFileChooser chooser = FileChooserFactory.getKeyStoreFileChooser();

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null)
        {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FKeyToolGUI.OpenKeyStore.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showOpenDialog(this);
        if (iRtnValue == JFileChooser.APPROVE_OPTION)
        {
            File fOpenFile = chooser.getSelectedFile();

            // File chosen - open the KeyStore
            if (openKeyStore(fOpenFile))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Open the supplied KeyStore file from disk.
     *
     * @param fKeyStore The KeyStore file
     * @return True if a KeyStore is opened, false otherwise
     */
    boolean openKeyStore(File fKeyStore) // Deliberately package private
    {
        // The KeyStore file is not a file
        if (!fKeyStore.isFile())
        {
            JOptionPane.showMessageDialog(this, MessageFormat.format(m_res.getString("FKeyToolGUI.NotFile.message"), new Object[]{fKeyStore}),
                                          m_res.getString("FKeyToolGUI.OpenKeyStore.Title"), JOptionPane.WARNING_MESSAGE);
            return false;
        }

        // Get the user to enter the KeyStore's password
        DGetPassword dGetPassword = new DGetPassword(this, MessageFormat.format(m_res.getString("FKeyToolGUI.GetKeyStorePassword.Title"), new String[]{fKeyStore.getName()}), true);
        dGetPassword.setLocationRelativeTo(this);
        dGetPassword.setVisible(true);
        char[] cPassword = dGetPassword.getPassword();

        if (cPassword == null)
        {
            return false;
        }

        try
        {
            // Load the KeyStore - try to open as each of the allowed types in turn until successful
            KeyStore openedKeyStore = null;

            // Types
            KeyStoreType[] keyStoreTypes = {KeyStoreType.JKS, KeyStoreType.JCEKS, KeyStoreType.PKCS12, KeyStoreType.BKS, KeyStoreType.UBER};

            // Exceptions
            CryptoException[] cexs = new CryptoException[keyStoreTypes.length];

            for (int iCnt=0; iCnt < keyStoreTypes.length; iCnt++)
            {
                try
                {
                    openedKeyStore = KeyStoreUtil.loadKeyStore(fKeyStore, cPassword, keyStoreTypes[iCnt]);
                    break; // Success
                }
                catch (CryptoException cex)
                {
                    cexs[iCnt] = cex;
                }
            }

            if (openedKeyStore == null)
            {
                // None of the types worked - show each of the errors?
                int iSelected = JOptionPane.showConfirmDialog(this, MessageFormat.format(m_res.getString("FKeyToolGUI.NoOpenKeyStore.message"), new Object[]{fKeyStore}),
                                                              m_res.getString("FKeyToolGUI.OpenKeyStore.Title"), JOptionPane.YES_NO_OPTION);
                if (iSelected == JOptionPane.YES_OPTION)
                {
                    for (int iCnt=0; iCnt < cexs.length; iCnt++)
                    {
                        displayException(cexs[iCnt]);
                    }
                }

                return false;
            }

            // Create a KeyStore wrapper for the KeyStore
            m_keyStoreWrap = new KeyStoreWrapper(openedKeyStore, fKeyStore, cPassword);

            // Update the frame's components and title
            updateControls();
            updateTitle();

            // Add KeyStore file to recent files in file menu
            m_jmrfFile.add(createRecentFileMenuItem(fKeyStore));

            // Update last accessed directory
            m_lastDir.updateLastDir(fKeyStore);

            return true;
        }
        catch (FileNotFoundException ex)
        {
            JOptionPane.showMessageDialog(this, MessageFormat.format(m_res.getString("FKeyToolGUI.NoReadFile.message"), new Object[]{fKeyStore}),
                                          m_res.getString("FKeyToolGUI.OpenKeyStore.Title"), JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (Exception ex)
        {
            displayException(ex);
            return false;
        }
    }

    /**
     * Save the currently opened KeyStore back to the file it was originally
     * opened from.
     *
     * @return True if the KeyStore is saved to disk, false otherwise
     */
    boolean saveKeyStore() // Deliberately package private
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // File to save to
        File fSaveFile = m_keyStoreWrap.getKeyStoreFile();

        // Not saved before - use Save As
        if (fSaveFile == null)
        {
            if (!saveKeyStoreAs())
            {
                return false; // Successful Save As
            }
            else
            {
                return true; // Failed Save As
            }
        }

        // Get the password to protect the KeyStore with
        char[] cPassword = m_keyStoreWrap.getPassword();

        // No password set for KeyStore - get one from the user
        if (cPassword == null)
        {
            cPassword = getNewKeyStorePassword();

            // User cancelled - cancel save
            if (cPassword == null)
            {
                return false;
            }
        }

        try
        {
            // Do the save
            KeyStoreUtil.saveKeyStore(m_keyStoreWrap.getKeyStore(), fSaveFile, cPassword);

            // Update the KeyStore wrapper
            m_keyStoreWrap.setPassword(cPassword);
            m_keyStoreWrap.setKeyStoreFile(fSaveFile);
            m_keyStoreWrap.setChanged(false);

            // Update the frame's components and title
            updateControls();
            updateTitle();

            return true;
        }
        catch (FileNotFoundException ex)
        {
            JOptionPane.showMessageDialog(this, MessageFormat.format(m_res.getString("FKeyToolGUI.NoWriteFile.message"), new Object[]{fSaveFile}),
                                          m_res.getString("FKeyToolGUI.SaveKeyStore.Title"), JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (Exception ex)
        {
            displayException(ex);
            return false;
        }
    }

    /**
     * Get a new KeyStore password.
     *
     * @return The new KeyStore password
     */
    private char[] getNewKeyStorePassword()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // Display the get new password dialog
        DGetNewPassword dGetNewPassword = new DGetNewPassword(this, m_res.getString("FKeyToolGUI.SetKeyStorePassword.Title"), true);
        dGetNewPassword.setLocationRelativeTo(this);
        dGetNewPassword.setVisible(true);

        // Dialog returned - retrieve the password and return it
        char[] cPassword = dGetNewPassword.getPassword();

        return cPassword;
    }

    /**
     * Save the currently opened KeyStore to disk to what may be a different
     * file from the one it was opened from (if any).
     *
     * @return True if the KeyStore is saved to disk, false otherwise
     */
    private boolean saveKeyStoreAs()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // KeyStore's current password
        char[] cPassword = m_keyStoreWrap.getPassword();

        // Get a new password if this KeyStore exists in another file or is an
        // unsaved KeyStore for which no password has been set yet
        if ((m_keyStoreWrap.getKeyStoreFile() != null) ||
            ((m_keyStoreWrap.getKeyStoreFile() == null) && (cPassword == null)))
        {
            cPassword = getNewKeyStorePassword();

            if (cPassword == null)
            {
                return false;
            }
        }

        // Let the user choose a save file
        JFileChooser chooser = FileChooserFactory.getKeyStoreFileChooser();

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null)
        {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FKeyToolGUI.SaveKeyStoreAs.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showSaveDialog(this);
        if (iRtnValue == JFileChooser.APPROVE_OPTION)
        {
            File fSaveFile = chooser.getSelectedFile();

            try
            {
                // Ask the user to overwrite if the chosen file exists already
                if (fSaveFile.isFile())
                {
                    String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.OverWriteFile.message"), new Object[]{fSaveFile});

                    int iSelected = JOptionPane.showConfirmDialog(this, sMessage, m_res.getString("FKeyToolGUI.SaveKeyStoreAs.Title"),
                                                                  JOptionPane.YES_NO_OPTION);
                    if (iSelected == JOptionPane.NO_OPTION)
                    {
                        return false;
                    }
                }

                // Save the KeyStore to file
                KeyStoreUtil.saveKeyStore(m_keyStoreWrap.getKeyStore(), fSaveFile, cPassword);

                // Update the KeyStore wrapper
                m_keyStoreWrap.setPassword(cPassword);
                m_keyStoreWrap.setKeyStoreFile(fSaveFile);
                m_keyStoreWrap.setChanged(false);

                // Update the frame's components and title
                updateControls();
                updateTitle();

                // Add KeyStore file to recent files in file menu
                m_jmrfFile.add(createRecentFileMenuItem(fSaveFile));

                m_lastDir.updateLastDir(fSaveFile);

                return true;
            }
            catch (FileNotFoundException ex)
            {
                JOptionPane.showMessageDialog(this, MessageFormat.format(m_res.getString("FKeyToolGUI.NoWriteFile.message"), new Object[]{fSaveFile}),
                                              m_res.getString("FKeyToolGUI.SaveKeyStoreAs.Title"), JOptionPane.WARNING_MESSAGE);
                return false;
            }
            catch (Exception ex)
            {
                displayException(ex);
                return false;
            }
        }
        return false;
    }

    /**
     * Check if the currently opened KeyStore requires to be saved.
     *
     * @return True if the KeyStore has been changed since the last open/save, false otherwise
     */
    boolean needSave()  // Deliberately package private
    {
        boolean bNeedSave = false;

        if (m_keyStoreWrap != null)
        {
            if (m_keyStoreWrap.isChanged())
            {
                bNeedSave = true;
            }
        }
        return bNeedSave;
    }

    /**
     * Ask the user if they want to save the current KeyStore file.
     *
     * @return JOptionPane.YES_OPTION, JOptionPane.NO_OPTION or JOptionPane.CANCEL_OPTION
     */
    int wantSave() // Deliberately package private
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        File fKeyStoreFile = m_keyStoreWrap.getKeyStoreFile();
        String sKeyStoreName;

        if (fKeyStoreFile != null)
        {
            sKeyStoreName = fKeyStoreFile.getName();
        }
        else
        {
            sKeyStoreName = m_res.getString("FKeyToolGUI.Untitled");
        }

        String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.WantSaveChanges.message"), new String[]{sKeyStoreName});

        int iSelected = JOptionPane.showConfirmDialog(this, sMessage,
                                                      m_res.getString("FKeyToolGUI.WantSaveChanges.Title"),
                                                      JOptionPane.YES_NO_CANCEL_OPTION);
        return iSelected;
    }

    /**
     * Create a new KeyStore file.
     *
     * @return True is a new KeyStore file is created, false otherwise
     */
    private boolean newKeyStore()
    {
        // Does the current KeyStore contain unsaved changes?
        if (needSave())
        {
            // Yes - ask the user if it should be saved
            int iWantSave = wantSave();

            if (iWantSave == JOptionPane.YES_OPTION)
            {
                // Save it
                if (!saveKeyStore())
                {
                    return false;
                }
            }
            else if (iWantSave == JOptionPane.CANCEL_OPTION)
            {
                return false;
            }
        }

        try
        {
            // Ask user for KeyStore type
            DNewKeyStoreType dNewKeyStoreType = new DNewKeyStoreType(this, true);
            dNewKeyStoreType.setLocationRelativeTo(this);
            dNewKeyStoreType.setVisible(true);

            KeyStoreType keyStoreType = dNewKeyStoreType.getKeyStoreType();

            // No keyStore type chosen
            if (keyStoreType == null)
            {
                return false;
            }

            // Create new KeyStore
            KeyStore newKeyStore = KeyStoreUtil.createKeyStore(keyStoreType);

            // Update the KeyStore wrapper
            m_keyStoreWrap = new KeyStoreWrapper(newKeyStore);
            m_keyStoreWrap.setChanged(true);

            // Update the frame's components and title
            updateControls();
            updateTitle();

            return true;
        }
        catch (Exception ex)
        {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user examine the contents of a certificate file.
     *
     * @return True if the user was able to examine the certificate file, false otherwise
     */
    private boolean examineCert()
    {
        // Let the user choose the certificate file to examine
        File fCertFile = chooseExamineCertFile();
        if (fCertFile == null)
        {
            return false;
        }

        // Get the certificates contained within the file
        X509Certificate[] certs = openCert(fCertFile);

        m_lastDir.updateLastDir(fCertFile);

        try
        {
            // If there are any display the view certificate dialog with them
            if ((certs != null) && (certs.length > 0))
            {
                DViewCertificate dViewCertificate =
                    new DViewCertificate(this, MessageFormat.format(m_res.getString("FKeyToolGUI.CertDetailsFile.Title"), new String[]{fCertFile.getName()}),
                                         true, certs);
                dViewCertificate.setLocationRelativeTo(this);
                dViewCertificate.setVisible(true);
                return true;
            }
            else
            {
                return false;
            }
        }
        catch (CryptoException ex)
        {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user examine the contents of a CRL file.
     *
     * @return True if the user was able to examine the CRL file, false otherwise
     */
    private boolean examineCRL()
    {
        // Let the user choose the certificate file to examine
        File fCRLFile = chooseExamineCRLFile();
        if (fCRLFile == null)
        {
            return false;
        }

        // Get the CRL contained within the file
        X509CRL crl = openCRL(fCRLFile);

        m_lastDir.updateLastDir(fCRLFile);

        // If a CRL is available then diaply the view CRL dialog with it
        if (crl != null)
        {
            DViewCRL dViewCRL =
                new DViewCRL(this, MessageFormat.format(m_res.getString("FKeyToolGUI.CrlDetailsFile.Title"), new String[]{fCRLFile.getName()}),
                             true, crl);
            dViewCRL.setLocationRelativeTo(this);
            dViewCRL.setVisible(true);
            return true;
        }
        else
        {
            return false;
        }
    }

    /**
     * Let the user choose a CA reply file to import.
     *
     * @return The chosen file or null if none was chosen
     */
    private File chooseImportCAFile()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        JFileChooser chooser = FileChooserFactory.getCertFileChooser();

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null)
        {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FKeyToolGUI.ImportCaReply.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this, m_res.getString("FKeyToolGUI.ImportCaReply.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION)
        {
            File fOpenFile = chooser.getSelectedFile();
            return fOpenFile;
        }
        return null;
    }

    /**
     * Let the user choose a certificate file to examine.
     *
     * @return The chosen file or null if none was chosen
     */
    private File chooseExamineCertFile()
    {
        JFileChooser chooser = FileChooserFactory.getCertFileChooser();

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null)
        {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FKeyToolGUI.ExamineCertificate.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this, m_res.getString("FKeyToolGUI.ExamineCertificate.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION)
        {
            File fOpenFile = chooser.getSelectedFile();
            return fOpenFile;
        }
        return null;
    }

    /**
     * Let the user choose a CRL file to examine.
     *
     * @return The chosen file or null if none was chosen
     */
    private File chooseExamineCRLFile()
    {
        JFileChooser chooser = FileChooserFactory.getCrlFileChooser();

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null)
        {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FKeyToolGUI.ExamineCrl.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this, m_res.getString("FKeyToolGUI.ExamineCrl.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION)
        {
            File fOpenFile = chooser.getSelectedFile();
            return fOpenFile;
        }
        return null;
    }

    /**
     * Let the user choose a trusted certificate file to import.
     *
     * @return The chosen file or null if none was chosen
     */
    private File chooseTrustCertFile()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        JFileChooser chooser = FileChooserFactory.getX509FileChooser();

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null)
        {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FKeyToolGUI.ImportTrustCert.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this, m_res.getString("FKeyToolGUI.ImportTrustCert.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION)
        {
            File fImportFile = chooser.getSelectedFile();
            return fImportFile;
        }
        return null;
    }

    /**
     * Let the user choose a PKCS #12 KeyStore file to import from.
     *
     * @return The chosen file or null if none was chosen
     */
    private File chooseImportPkcs12File()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        JFileChooser chooser = FileChooserFactory.getPkcs12FileChooser();

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null)
        {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FKeyToolGUI.ImportPkcs12KeyStore.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this, m_res.getString("FKeyToolGUI.ImportPkcs12KeyStore.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION)
        {
            File fPkcs12File = chooser.getSelectedFile();
            return fPkcs12File;
        }
        return null;
    }

    /**
     * Let the user choose a file to generate a CSR in.
     *
     * @return The chosen file or null if none was chosen
     */
    private File chooseGenerateCsrFile()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        JFileChooser chooser = FileChooserFactory.getCsrFileChooser();

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null)
        {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FKeyToolGUI.GenerateCsr.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this, m_res.getString("FKeyToolGUI.GenerateCsr.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION)
        {
            File fCsrFile = chooser.getSelectedFile();
            return fCsrFile;
        }
        return null;
    }

    /**
     * Open a certificate file.
     *
     * @param fCertFile The certificate file
     * @return The certificates found in the file or null if there were none
     */
    private X509Certificate[] openCert(File fCertFile)
    {
        try
        {
            X509Certificate[] certs = X509CertUtil.loadCertificates(fCertFile);
            if (certs.length == 0)
            {
                JOptionPane.showMessageDialog(this, MessageFormat.format(m_res.getString("FKeyToolGUI.NoCertsFound.message"), new Object[]{fCertFile}),
                                              m_res.getString("FKeyToolGUI.OpenCertificate.Title"), JOptionPane.WARNING_MESSAGE);
            }

            return certs;
        }
        catch (FileNotFoundException ex)
        {
            JOptionPane.showMessageDialog(this, MessageFormat.format(m_res.getString("FKeyToolGUI.NoReadFile.message"), new Object[]{fCertFile}),
                                          m_res.getString("FKeyToolGUI.OpenCertificate.Title"), JOptionPane.WARNING_MESSAGE);
            return null;
        }
        catch (Exception ex)
        {
            displayException(ex);
            return null;
        }
    }

    /**
     * Open a CRL file.
     *
     * @param fCRLFile The CRL file
     * @return The CRL found in the file or null if there wasn't one
     */
    private X509CRL openCRL(File fCRLFile)
    {
        try
        {
            X509CRL crl = X509CertUtil.loadCRL(fCRLFile);
            return crl;
        }
        catch (FileNotFoundException ex)
        {
            JOptionPane.showMessageDialog(this, MessageFormat.format(m_res.getString("FKeyToolGUI.NoReadFile.message"), new Object[]{fCRLFile}),
                                          MessageFormat.format(m_res.getString("FKeyToolGUI.CrlDetailsFile.Title"), new String[]{fCRLFile.getName()}), JOptionPane.WARNING_MESSAGE);
            return null;
        }
        catch (Exception ex)
        {
            displayException(ex);
            return null;
        }
    }

    /**
     * Let the user import a CA reply into the selected key pair entry.
     *
     * @return True if the import is successful, false otherwise
     */
    private boolean importCAReplySelectedEntry()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // What entry is selected?
        int iRow = m_jtKeyStore.getSelectedRow();

        if (iRow == -1)
        {
            return false;
        }

        String sAlias = (String)m_jtKeyStore.getValueAt(iRow, 1);

        // Get the KeyStore
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        // Let the user choose a file for the trusted certificate
        File fCertFile = chooseImportCAFile();
        if (fCertFile == null)
        {
            return false;
        }

        // Load the certificate(s)
        X509Certificate[] certs = openCert(fCertFile);

        if ((certs == null) || (certs.length == 0))
        {
            return false;
        }

        try
        {
            // Order the new certificates into a chain...
            certs = X509CertUtil.orderX509CertChain(certs);

            // ...and those that exist in the entry already
            X509Certificate[] oldCerts = X509CertUtil.orderX509CertChain(
                X509CertUtil.convertCertificates(keyStore.getCertificateChain(sAlias))
            );

            // Compare the public keys of the start of each chain
            if (!oldCerts[0].getPublicKey().equals(certs[0].getPublicKey()))
            {
                JOptionPane.showMessageDialog(this, m_res.getString("FKeyToolGUI.NoMatchPubKeyCaReply.message"),
                                              m_res.getString("FKeyToolGUI.ImportCaReply.Title"), JOptionPane.ERROR_MESSAGE);
                return false;
            }

            // If the CA Certs KeyStore is to be used and it has yet to be loaded then do so
            if ((m_bUseCaCerts) && (m_caCertsKeyStore == null))
            {
                m_caCertsKeyStore = openCaCertsKeyStore();
                if (m_caCertsKeyStore == null)
                {
                    // Failed to load CA Certs KeyStore
                    return false;
                }
            }

            // Holds the new certificate chain for the entry should the import succeed
            X509Certificate[] newCertChain = null;

            /* PKCS#7 reply - try and match the self-signed root with any of the
               certificates in the CA Certs or current KeyStore */
            if (certs.length > 1)
            {
                X509Certificate rootCert = certs[certs.length - 1];
                String sMatchAlias = null;

                if (m_bUseCaCerts) // Match against CA Certs KeyStore
                {
                    sMatchAlias = X509CertUtil.matchCertificate(m_caCertsKeyStore, rootCert);
                }

                if (sMatchAlias == null) // Match against current KeyStore
                {
                    sMatchAlias = X509CertUtil.matchCertificate(keyStore, rootCert);
                }

                // No match
                if (sMatchAlias == null)
                {
                    // Tell the user what is happening
                    JOptionPane.showMessageDialog(this, m_res.getString("FKeyToolGUI.NoMatchRootCertCaReplyConfirm.message"),
                                                  m_res.getString("FKeyToolGUI.ImportCaReply.Title"), JOptionPane.INFORMATION_MESSAGE);

                    // Display the certficate to the user
                    DViewCertificate dViewCertificate =
                        new DViewCertificate(this, MessageFormat.format(m_res.getString("FKeyToolGUI.CertDetailsFile.Title"), new String[]{fCertFile.getName()}),
                                             true, new X509Certificate[]{rootCert});
                    dViewCertificate.setLocationRelativeTo(this);
                    dViewCertificate.setVisible(true);

                    // Request confirmation that the certidicate is to be trusted
                    int iSelected = JOptionPane.showConfirmDialog(this, m_res.getString("FKeyToolGUI.AcceptCaReply.message"),
                                                                  m_res.getString("FKeyToolGUI.ImportCaReply.Title"),
                                                                  JOptionPane.YES_NO_OPTION);
                    if (iSelected == JOptionPane.NO_OPTION)
                    {
                        return false;
                    }
                    newCertChain = certs;
                }
                else
                {
                    newCertChain = certs;
                }
            }
            /* Single X.509 certificate reply - try and establish a chain of
               trust from the certificate and ending with a root CA self-signed
               certificate */
            else
            {
                KeyStore[] compKeyStores = null;

                if (m_bUseCaCerts) // Establish against CA Certs KeyStore and current KeyStore
                {
                    compKeyStores = new KeyStore[]{m_caCertsKeyStore, keyStore};
                }
                else // Establish against current KeyStore only
                {
                    compKeyStores = new KeyStore[]{keyStore};
                }

                X509Certificate[] trustChain = X509CertUtil.establishTrust(compKeyStores, certs[0]);

                if (trustChain != null)
                {
                    newCertChain = trustChain;
                }
                else
                {
                    JOptionPane.showMessageDialog(this, m_res.getString("FKeyToolGUI.NoTrustCaReply.message"),
                                                  m_res.getString("FKeyToolGUI.ImportCaReply.Title"),
                                                  JOptionPane.ERROR_MESSAGE);
                    return false;
                }
            }

            // Get the entry's password (we may already know it from the wrapper)
            char[] cPassword = m_keyStoreWrap.getEntryPassword(sAlias);

            if (cPassword == null)
            {
                cPassword = PKCS12_DUMMY_PASSWORD;

                // Password is only relevant if the KeyStore is not PKCS #12
                if (!keyStore.getType().equals(KeyStoreType.PKCS12.toString()))
                {
                    DGetPassword dGetPassword = new DGetPassword(this,  m_res.getString("FKeyToolGUI.KeyEntryPassword.Title"), true);
                    dGetPassword.setLocationRelativeTo(this);
                    dGetPassword.setVisible(true);
                    cPassword = dGetPassword.getPassword();

                    if (cPassword == null)
                    {
                        return false;
                    }
                }
            }

            // Replace the certificate chain
            Key privKey = keyStore.getKey(sAlias, cPassword);
            keyStore.deleteEntry(sAlias);
            keyStore.setKeyEntry(sAlias, privKey, cPassword, newCertChain);

            // Update the KeyStore wrapper
            m_keyStoreWrap.setChanged(true);
            m_keyStoreWrap.setEntryPassword(sAlias, cPassword);

            // Update the frame's components and title
            updateControls();
            updateTitle();

            m_lastDir.updateLastDir(fCertFile);

            // Display success message
            JOptionPane.showMessageDialog(this, m_res.getString("FKeyToolGUI.ImportCaReplySuccessful.message"),
                                          m_res.getString("FKeyToolGUI.ImportCaReply.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);

            return true;
        }
        catch (Exception ex)
        {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user import a trusted certificate.
     *
     * @return True if the import is successful, false otherwise
     */
    private boolean importTrustedCert()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // Let the user choose a file for the trusted certificate
        File fCertFile = chooseTrustCertFile();
        if (fCertFile == null)
        {
            return false;
        }

        // Load the certificate(s)
        X509Certificate[] certs = openCert(fCertFile);

        if ((certs == null) || (certs.length == 0))
        {
            return false;
        }

        if (certs.length >  1)
        {
            // Cannot import more than one certificate
            JOptionPane.showMessageDialog(this, m_res.getString("FKeyToolGUI.NoMultipleTrustCertImport.message"),
                                          m_res.getString("FKeyToolGUI.ImportTrustCert.Title"), JOptionPane.ERROR_MESSAGE);
            return false;
        }

        X509Certificate trustCert = certs[0];

        try
        {
            // Get the KeyStore
            KeyStore keyStore = m_keyStoreWrap.getKeyStore();

            // Certificate already exists in the KeyStore
            String sMatchAlias = X509CertUtil.matchCertificate(keyStore, trustCert);
            if (sMatchAlias != null)
            {
                int iSelected = JOptionPane.showConfirmDialog(this, MessageFormat.format(m_res.getString("FKeyToolGUI.TrustCertExistsConfirm.message"), new String[]{sMatchAlias}),
                                                              m_res.getString("FKeyToolGUI.ImportTrustCert.Title"),
                                                              JOptionPane.YES_NO_OPTION);
                if (iSelected == JOptionPane.NO_OPTION)
                {
                    return false;
                }
            }

            // If the CA Certs KeyStore is to be used and it has yet to be loaded
            // then do so
            if ((m_bUseCaCerts) && (m_caCertsKeyStore == null))
            {
                m_caCertsKeyStore = openCaCertsKeyStore();
                if (m_caCertsKeyStore == null)
                {
                    // Failed to load CA Certs KeyStore
                    return false;
                }
            }

            // If we cannot establish trust for the certificate against the
            // CA Certs KeyStore or the current KeyStore then display the certficate
            // to the user for confirmation
            KeyStore[] compKeyStores = null;

            if (m_bUseCaCerts) // Establish against CA Certs KeyStore and current KeyStore
            {
                compKeyStores = new KeyStore[]{m_caCertsKeyStore, keyStore};
            }
            else // Establish against current KeyStore only
            {
                compKeyStores = new KeyStore[]{keyStore};
            }

            if (X509CertUtil.establishTrust(compKeyStores, trustCert) == null)
            {
                // Tell the user what is happening
                JOptionPane.showMessageDialog(this, m_res.getString("FKeyToolGUI.NoTrustPathCertConfirm.message"),
                                              m_res.getString("FKeyToolGUI.ImportTrustCert.Title"),
                                              JOptionPane.INFORMATION_MESSAGE);

                // Display the certficate to the user
                DViewCertificate dViewCertificate =
                    new DViewCertificate(this, MessageFormat.format(m_res.getString("FKeyToolGUI.CertDetailsFile.Title"), new String[]{fCertFile.getName()}),
                                         true, new X509Certificate[]{trustCert});
                dViewCertificate.setLocationRelativeTo(this);
                dViewCertificate.setVisible(true);

                // Request confirmation that the certidicate is to be trusted
                int iSelected = JOptionPane.showConfirmDialog(this, m_res.getString("FKeyToolGUI.AcceptTrustCert.message"),
                                                              m_res.getString("FKeyToolGUI.ImportTrustCert.Title"),
                                                              JOptionPane.YES_NO_OPTION);
                if (iSelected == JOptionPane.NO_OPTION)
                {
                    return false;
                }
            }

            // Get the entry alias to put the trusted certificate into
            DGetAlias dGetAlias = new DGetAlias(this, m_res.getString("FKeyToolGUI.TrustCertEntryAlias.Title"), true, X509CertUtil.getCertificateAlias(trustCert));
            dGetAlias.setLocationRelativeTo(this);
            dGetAlias.setVisible(true);
            String sAlias = dGetAlias.getAlias();

            if (sAlias == null)
            {
                return false;
            }

            // Check entry does not already exist in the KeyStore
            if (keyStore.containsAlias(sAlias))
            {
                String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.OverWriteEntry.message"), new String[]{sAlias});

                int iSelected = JOptionPane.showConfirmDialog(this, sMessage, m_res.getString("FKeyToolGUI.ImportTrustCert.Title"),
                                                              JOptionPane.YES_NO_OPTION);
                if (iSelected == JOptionPane.NO_OPTION)
                {
                    return false;
                }
                // Otherwise carry on - delete entry to be copied over
                keyStore.deleteEntry(sAlias);
            }

            // Import the trusted certificate
            keyStore.setCertificateEntry(sAlias, trustCert);

            // Update the KeyStore wrapper
            m_keyStoreWrap.setChanged(true);

            // Update the frame's components and title
            updateControls();
            updateTitle();

            m_lastDir.updateLastDir(fCertFile);

            // Display success message
            JOptionPane.showMessageDialog(this, m_res.getString("FKeyToolGUI.ImportTrustCertSuccessful.message"), m_res.getString("FKeyToolGUI.ImportTrustCert.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);

            return true;
        }
        catch (Exception ex)
        {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user import a key pair from a PKCS #12 KeyStore.
     *
     * @return True if the import is successful, false otherwise
     */
    private boolean importKeyPair()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        // Let the user choose a a PKCS #12 KeyStore file
        File fPkcs12 = chooseImportPkcs12File();
        if (fPkcs12 == null)
        {
            return false;
        }

        // The PKCS #12 file is not a file
        if (!fPkcs12.isFile())
        {
            JOptionPane.showMessageDialog(this, MessageFormat.format(m_res.getString("FKeyToolGUI.NotFile.message"), new Object[]{fPkcs12}),
                                          m_res.getString("FKeyToolGUI.ImportKeyPair.Title"), JOptionPane.WARNING_MESSAGE);
            return false;
        }

        // Get the user to enter the PKCS #12 KeyStore's password
        DGetPassword dGetPassword = new DGetPassword(this,  m_res.getString("FKeyToolGUI.Pkcs12Password.Title"), true);
        dGetPassword.setLocationRelativeTo(this);
        dGetPassword.setVisible(true);
        char[] cPkcs12Password = dGetPassword.getPassword();

        if (cPkcs12Password == null)
        {
            return false;
        }

        try
        {
            // Load the PKCS #12 KeyStore
            KeyStore pkcs12 = KeyStoreUtil.loadKeyStore(fPkcs12, cPkcs12Password, KeyStoreType.PKCS12);

            m_lastDir.updateLastDir(fPkcs12);

            // Display the import key pair dialog supplying the PKCS #12 KeyStore to it
            DImportKeyPair dImportKeyPair = new DImportKeyPair(this, true, pkcs12);
            dImportKeyPair.setLocationRelativeTo(this);
            dImportKeyPair.setVisible(true);

            // Get the private key and certificate chain of the key pair
            Key privateKey = dImportKeyPair.getPrivateKey();
            Certificate[] certs = dImportKeyPair.getCertificateChain();

            if ((privateKey == null) || (certs == null))
            {
                // User did not select a key pair for import
                return false;
            }

            // Get an alias for the new KeyStore entry
            String sAlias = null;

            // Get the alias for the new key pair entry
            DGetAlias dGetAlias =
                new DGetAlias(this, m_res.getString("FKeyToolGUI.KeyPairEntryAlias.Title"), true,
                              X509CertUtil.getCertificateAlias(X509CertUtil.convertCertificate(certs[0])));
            dGetAlias.setLocationRelativeTo(this);
            dGetAlias.setVisible(true);
            sAlias = dGetAlias.getAlias();

            if (sAlias == null)
            {
                return false;
            }

            // Check an entry with the selected does not already exist in the KeyStore
            if (keyStore.containsAlias(sAlias))
            {
                String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.OverWriteEntry.message"), new String[]{sAlias});

                int iSelected = JOptionPane.showConfirmDialog(this, sMessage, m_res.getString("FKeyToolGUI.KeyPairEntryAlias.Title"),
                                                              JOptionPane.YES_NO_CANCEL_OPTION);
                if (iSelected == JOptionPane.CANCEL_OPTION)
                {
                    return false;
                }
                else if (iSelected == JOptionPane.NO_OPTION)
                {
                    return false;
                }
                // Otherwise carry on - delete entry to be copied over
                keyStore.deleteEntry(sAlias);
            }

            // Get a password for the new KeyStore entry (only relevant if the KeyStore is not PKCS #12)
            char[] cPassword = PKCS12_DUMMY_PASSWORD;

            if (!keyStore.getType().equals(KeyStoreType.PKCS12.toString()))
            {
                DGetNewPassword dGetNewPassword = new DGetNewPassword(this, m_res.getString("FKeyToolGUI.KeyEntryPassword.Title"), true);
                dGetNewPassword.setLocationRelativeTo(this);
                dGetNewPassword.setVisible(true);
                cPassword = dGetNewPassword.getPassword();

                if (cPassword == null)
                {
                    return false;
                }
            }

            // Place the private key and certificate chain into the KeyStore and update
            // the KeyStore wrapper
            keyStore.setKeyEntry(sAlias, privateKey, cPassword, certs);
            m_keyStoreWrap.setEntryPassword(sAlias, cPassword);
            m_keyStoreWrap.setChanged(true);

            // Update the frame's components and title
            updateControls();
            updateTitle();

            // Display success message
            JOptionPane.showMessageDialog(this, m_res.getString("FKeyToolGUI.KeyPairImportSuccessful.message"),
                                          m_res.getString("FKeyToolGUI.ImportKeyPair.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);
            return true;
        }
        catch (Exception ex)
        {
            displayException(ex);
            return false;
        }
    }

    /**
     * Open the CA Certs KeyStore from disk.
     *
     * @return The KeyStore if it could be openend or null otherwise
     */
    private KeyStore openCaCertsKeyStore()
    {
        // Get the user to enter the CA Certs KeyStore's password
        DGetPassword dGetPassword = new DGetPassword(this, m_res.getString("FKeyToolGUI.CaCertsKeyStorePassword.Title"), true);
        dGetPassword.setLocationRelativeTo(this);
        dGetPassword.setVisible(true);
        char[] cPassword = dGetPassword.getPassword();

        if (cPassword == null)
        {
            return null;
        }

        try
        {
            // Load the CA Certs KeyStore - try to open as each of the allowed types in turn until successful
            KeyStore caCertsKeyStore = null;

            // Types
            KeyStoreType[] keyStoreTypes = {KeyStoreType.JKS, KeyStoreType.JCEKS, KeyStoreType.PKCS12, KeyStoreType.BKS, KeyStoreType.UBER};

            // Exceptions
            CryptoException[] cexs = new CryptoException[keyStoreTypes.length];

            for (int iCnt=0; iCnt < keyStoreTypes.length; iCnt++)
            {
                try
                {
                    caCertsKeyStore = KeyStoreUtil.loadKeyStore(m_fCaCertsFile, cPassword, keyStoreTypes[iCnt]);
                    break; // Success
                }
                catch (CryptoException cex)
                {
                    cexs[iCnt] = cex;
                }
            }

            if (caCertsKeyStore == null)
            {
                // None of the types worked - show each of the errors?
                int iSelected = JOptionPane.showConfirmDialog(this, MessageFormat.format(m_res.getString("FKeyToolGUI.NoOpenCaCertsKeyStore.message"), new Object[]{m_fCaCertsFile}),
                                                              m_res.getString("FKeyToolGUI.OpenCaCertsKeyStore.Title"), JOptionPane.YES_NO_OPTION);
                if (iSelected == JOptionPane.YES_OPTION)
                {
                    for (int iCnt=0; iCnt < cexs.length; iCnt++)
                    {
                        displayException(cexs[iCnt]);
                    }
                }

                return null;
            }

            return caCertsKeyStore;
        }
        catch (FileNotFoundException ex)
        {
            JOptionPane.showMessageDialog(this, MessageFormat.format(m_res.getString("FKeyToolGUI.NoReadFile.message"), new Object[]{m_fCaCertsFile}),
                                          m_res.getString("FKeyToolGUI.OpenCaCertsKeyStore.Title"), JOptionPane.WARNING_MESSAGE);
            return null;
        }
        catch (Exception ex)
        {
            displayException(ex);
            return null;
        }
    }

    /**
     * Display the help dialog.
     */
    private void showHelp()
    {
        // Create the dialog if it does not already exist
        if (m_fHelp == null)
        {
            URL toc = getClass().getResource(m_res.getString("FKeyToolGUI.Help.Contents"));
            URL home = getClass().getResource(m_res.getString("FKeyToolGUI.Help.Home"));

            m_fHelp = new FHelp(m_res.getString("FKeyToolGUI.Help.Title"), home, toc);
            m_fHelp.setLocation(getX() + 25, getY() + 25);
            m_fHelp.setVisible(true);
        }

        // Show the help dialog
        m_fHelp.setVisible(true);
    }

    /**
     * Display application's website.
     */
    private void visitWebsite()
    {
        String sWebsiteAddress = m_res.getString("FKeyToolGUI.WebsiteAddress");

        try
        {
            BrowserLauncher.openURL(sWebsiteAddress);
        }
        catch (IOException ex)
        {
            // Could not launch web browser - tell the user the address
            JOptionPane.showMessageDialog(this,
                                          MessageFormat.format(m_res.getString("FKeyToolGUI.NoLaunchBrowser.message"), new String[]{sWebsiteAddress}),
                                          m_res.getString("FKeyToolGUI.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * Display Portecle project page at SourceForge.net.
     */
    private void visitSFNetProject()
    {
        String sWebsiteAddress = m_res.getString("FKeyToolGUI.SFNetProjectAddress");

        try
        {
            BrowserLauncher.openURL(sWebsiteAddress);
        }
        catch (IOException ex)
        {
            // Could not launch web browser - tell the user the address
            JOptionPane.showMessageDialog(this,
                                          MessageFormat.format(m_res.getString("FKeyToolGUI.NoLaunchBrowser.message"), new String[]{sWebsiteAddress}),
                                          m_res.getString("FKeyToolGUI.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * Compose email to application author.
     */
    private void composeEmail()
    {
        String sEmailAddress = m_res.getString("FKeyToolGUI.EmailAddress");

        try
        {
            // Could not launch email client - tell the user the address
            BrowserLauncher.openURL(MessageFormat.format("mailto:{0}", new String[]{sEmailAddress}));
        }
        catch (IOException ex)
        {
            JOptionPane.showMessageDialog(this,
                                          MessageFormat.format(m_res.getString("FKeyToolGUI.NoLaunchEmail.message"), new String[]{sEmailAddress}),
                                          m_res.getString("FKeyToolGUI.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * Display Portecle mailing list signup page at SourceForge.net.
     */
    private void visitMailListSignup()
    {
        String sMailListSignupAddress = m_res.getString("FKeyToolGUI.MailListSignupAddress");

        try
        {
            BrowserLauncher.openURL(sMailListSignupAddress);
        }
        catch (IOException ex)
        {
            // Could not launch web browser - tell the user the address
            JOptionPane.showMessageDialog(this,
                                          MessageFormat.format(m_res.getString("FKeyToolGUI.NoLaunchBrowser.message"), new String[]{sMailListSignupAddress}),
                                          m_res.getString("FKeyToolGUI.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * Check if a more up-to-date version of KeyTool GUI exists by querying
     * a properties file on the internet.
     */
    private void checkForUpdate()
    {
        // Get the version number of this KeyTool GUI
        String sCurrentVersion = m_res.getString("FKeyToolGUI.Version");

        HttpURLConnection urlConn = null;
        ObjectInputStream ois = null;

        try
        {
            /* Get the version number of the latest KeyTool GUI from the Internet - present in
               a serialised Version object on the KeyTool GUI web site */

            // Build and connect to the relevant URL
            URL latestVersionUrl = new URL(m_res.getString("FKeyToolGUI.LatestVersionAddress"));
            urlConn = (HttpURLConnection)latestVersionUrl.openConnection();

            int iResponseCode = urlConn.getResponseCode();
            if (iResponseCode != HttpURLConnection.HTTP_OK)
            {
                // Bad response code from server
                JOptionPane.showMessageDialog(
                    this,
                    MessageFormat.format(m_res.getString("FKeyToolGUI.Non200Response.message"), new Object[]{""+iResponseCode, latestVersionUrl}),
                    m_res.getString("FKeyToolGUI.Title"),
                    JOptionPane.ERROR_MESSAGE
                );
                return;
            }

            /* Current hosting goes through a frame redirect - this is indicated by content type being HTML.
               When the redirection is removed in future this code block will not be called */
            if (urlConn.getContentType().equals("text/html"))
            {
                // Parse redirection HTML for the real URL of the Version file
                URL redirectionUrl = RedirectParser.getRedirectUrl(urlConn);

                // Disconnect current connection
                urlConn.disconnect();

                if (redirectionUrl == null)
                {
                    // No redirection URL found
                    JOptionPane.showMessageDialog(this,
                                                  MessageFormat.format(m_res.getString("FKeyToolGUI.NoFindRedirect.message"), new Object[]{latestVersionUrl}),
                                                  m_res.getString("FKeyToolGUI.Title"),
                                                  JOptionPane.ERROR_MESSAGE);
                    return;
                }

                latestVersionUrl = redirectionUrl;

                // Replace connection with a new one to the redirection URL
                urlConn = (HttpURLConnection)latestVersionUrl.openConnection();

                iResponseCode = urlConn.getResponseCode();
                if (iResponseCode != HttpURLConnection.HTTP_OK)
                {
                    // Bad response code from server
                    JOptionPane.showMessageDialog(
                        this,
                        MessageFormat.format(m_res.getString("FKeyToolGUI.Non200Response.message"), new Object[]{""+iResponseCode, latestVersionUrl}),
                        m_res.getString("FKeyToolGUI.Title"),
                        JOptionPane.ERROR_MESSAGE
                    );
                    return;
                }
            }

            // Attempt to read serialized Version into an object
            ois = new ObjectInputStream(urlConn.getInputStream());
            Version latestVersion = (Version)ois.readObject();

            // Construct current version into a Version object for comparison
            Version currentVersion = new Version(sCurrentVersion);

            // Make comparison
            int iCmp = currentVersion.compareTo(latestVersion);

            if (iCmp >= 0)
            {
                // Latest version same (or less!) then current version - tell user they are up-to-date
                JOptionPane.showMessageDialog(this,
                                              MessageFormat.format(m_res.getString("FKeyToolGUI.HaveLatestVersion.message"), new Object[]{currentVersion}),
                                              m_res.getString("FKeyToolGUI.Title"),
                                              JOptionPane.INFORMATION_MESSAGE);
            }
            else
            {
                int iSelected = JOptionPane.showConfirmDialog(
                    this,
                    MessageFormat.format(m_res.getString("FKeyToolGUI.NewerVersionAvailable.message"), new Object[]{latestVersion, m_res.getString("FKeyToolGUI.DownloadsAddress")}),
                    m_res.getString("FKeyToolGUI.Title"), JOptionPane.YES_NO_OPTION);
                if (iSelected == JOptionPane.YES_OPTION)
                {
                    visitDownloads();
                }
            }
        }
        // Display errors to user
        catch (VersionException ex)
        {
            displayException(ex);
        }
        catch (ClassNotFoundException ex)
        {
            displayException(ex);
        }
        catch (IOException ex)
        {
            displayException(ex);
        }
        finally
        {
            // Clean-up
            if (urlConn != null)
            {
                urlConn.disconnect();
            }

            if (ois != null)
            {
                try { ois.close(); } catch (IOException ex) { /* Ignore */ }
            }
        }
    }

    /**
     * Display teh KeyTool GUI downloads web page.
     */
    private void visitDownloads()
    {
        String sDownloadsAddress = m_res.getString("FKeyToolGUI.DownloadsAddress");

        try
        {
            BrowserLauncher.openURL(sDownloadsAddress);
        }
        catch (IOException ex)
        {
            // Could not launch web browser - tell the user the address
            JOptionPane.showMessageDialog(this,
                                          MessageFormat.format(m_res.getString("FKeyToolGUI.NoLaunchBrowser.message"), new String[]{sDownloadsAddress}),
                                          m_res.getString("FKeyToolGUI.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * Display PayPal donation web page.
     */
    private void makeDonation()
    {
        int iSelected = JOptionPane.showConfirmDialog(this, m_res.getString("FKeyToolGUI.Donation.message"),
                                                      m_res.getString("FKeyToolGUI.Title"), JOptionPane.YES_NO_OPTION);
        if (iSelected == JOptionPane.YES_OPTION)
        {
            String sDonateAddress = m_res.getString("FKeyToolGUI.DonateAddress");

            try
            {
                BrowserLauncher.openURL(sDonateAddress);
            }
            catch (IOException ex)
            {
                // Could not launch web browser - tell the user the address
                JOptionPane.showMessageDialog(this,
                                              MessageFormat.format(m_res.getString("FKeyToolGUI.NoLaunchBrowser.message"), new String[]{sDonateAddress}),
                                              m_res.getString("FKeyToolGUI.Title"),
                                              JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    /**
     * Display Security Provider Information dialog.
     */
    private void showSecurityProviders()
    {
        DProviderInfo dProviderInfo = new DProviderInfo(this, true);
        dProviderInfo.setLocationRelativeTo(this);
        dProviderInfo.setVisible(true);
    }

    /**
     * Display JAR Information dialog.
     */
    private void showJarInfo()
    {
        try
        {
            DJarInfo dJarInfo = new DJarInfo(this, true);
            dJarInfo.setLocationRelativeTo(this);
            dJarInfo.setVisible(true);
        }
        catch (IOException ex)
        {
            displayException(ex);
        }
    }

    /**
     * Display the options dialog and store the user's choices.
     */
    private void showOptions()
    {
        DOptions dOptions = new DOptions(this, true, m_bUseCaCerts, m_fCaCertsFile);
        dOptions.setLocationRelativeTo(this);
        dOptions.setVisible(true);

        // Store/apply the chosen options:

        // CA Certs file
        File fTmp = dOptions.getCaCertsFile();

        if (!fTmp.equals(m_fCaCertsFile))
        {
            // CA Certs file changed - any stored CA Certs KeyStore is now invalid
            m_caCertsKeyStore = null;
        }

        m_fCaCertsFile = fTmp;

        // Use CA Certs?
        m_bUseCaCerts = dOptions.getUseCaCerts();

        // Look & feel
        UIManager.LookAndFeelInfo lookFeelInfo = dOptions.getLookFeelInfo();

        // Look & feel decoration
        boolean bLookFeelDecoration = dOptions.getLookFeelDecoration();

        // Look & feel/decoration changed?
        if (lookFeelInfo != null)
        {
            if ((!lookFeelInfo.getName().equals(UIManager.getLookAndFeel().getName())) ||
                (bLookFeelDecoration != JFrame.isDefaultLookAndFeelDecorated()))
            {
                // Yes - save selections to be picked up by app properties save and exit application
                JOptionPane.showMessageDialog(this, m_res.getString("FKeyToolGUI.LookFeelChanged.message"),
											  m_res.getString("FKeyToolGUI.LookFeelChanged.Title"),
											  JOptionPane.INFORMATION_MESSAGE);

                m_lookFeelOptions = lookFeelInfo;
                m_bLookFeelDecorationOptions = new Boolean(bLookFeelDecoration);

                exitApplication();
            }
        }
    }

    /**
     * Convert the loaded KeyStore's type to that supplied.
     *
     * @param keyStoreType New KeyStore type
     * @return True if the KeyStore's type was changed, false otherwise
     */
    private boolean changeKeyStoreType(KeyStoreType keyStoreType)
    {
        assert m_keyStoreWrap.getKeyStore() != null;
        assert (!m_keyStoreWrap.getKeyStore().getType().equals(keyStoreType.toString())); // Cannot change type to current type

        try
        {
            // Get current KeyStore and type
            KeyStore currentKeyStore = m_keyStoreWrap.getKeyStore();
            String sCurrentType = m_keyStoreWrap.getKeyStore().getType();

            // Create empty KeyStore of new type
            KeyStore newKeyStore = KeyStoreUtil.createKeyStore(keyStoreType);

            /* Flag used to tell if we have warned the user about default key pair entry passwords for
               KeyStores changed to PKCS #12 */
            boolean bWarnPkcs12Password = false;

            /* Flag used to tell if we have warned the user about key entries not being carried over by the change */
            boolean bWarnNoChangeKey = false;

            /* For every entry in the current KeyStore transfer it to the new one - get key/key pair entry passwords
               from the wrapper and if not present there from the user */
            for (Enumeration aliases = currentKeyStore.aliases(); aliases.hasMoreElements();)
            {
                // Entry alias
                String sAlias = (String)aliases.nextElement();

                // Trusted certificate entry
                if (currentKeyStore.isCertificateEntry(sAlias))
                {
                    // Get trusted certificate and place it in the new KeyStore
                    Certificate trustedCertificate = currentKeyStore.getCertificate(sAlias);
                    newKeyStore.setCertificateEntry(sAlias, trustedCertificate);
                }
                // Key or Key pair entry
                else if (currentKeyStore.isKeyEntry(sAlias))
                {
                    // Get certificate chain - will be null if entry is key
                    Certificate[] certificateChain = currentKeyStore.getCertificateChain(sAlias);

                    if ((certificateChain == null) || (certificateChain.length == 0))
                    {
                        // Key entries are not transferred - warn the user if we have no done so already
                        if (!bWarnNoChangeKey)
                        {
                            bWarnNoChangeKey = true;
                            int iSelected = JOptionPane.showConfirmDialog(this, m_res.getString("FKeyToolGUI.WarnNoChangeKey.message"),
                                                                          m_res.getString("FKeyToolGUI.ChangeKeyStoreType.Title"), JOptionPane.YES_NO_OPTION);
                            if (iSelected == JOptionPane.NO_OPTION)
                            {
                                return false;
                            }
                        }

                        continue;
                    }

                    // Get the entry's password (we may already know it from the wrapper)
                    char[] cPassword = m_keyStoreWrap.getEntryPassword(sAlias);

                    if (cPassword == null)
                    {
                        cPassword = PKCS12_DUMMY_PASSWORD;

                        // Password is only relevant if the current KeyStore type is not PKCS #12
                        if (!sCurrentType.equals(KeyStoreType.PKCS12.toString()))
                        {
                            DGetPassword dGetPassword = new DGetPassword(this, MessageFormat.format(m_res.getString("FKeyToolGUI.ChangeKeyStoreTypeKeyPairEntryPassword.Title"), new String[]{sAlias}), true);
                            dGetPassword.setLocationRelativeTo(this);
                            dGetPassword.setVisible(true);
                            cPassword = dGetPassword.getPassword();

                            if (cPassword == null)
                            {
                                return false;
                            }
                        }
                    }

                    // Use password to get keypair
                    Key key = currentKeyStore.getKey(sAlias, cPassword);

                    // The current KeyStore type is PKCS #12 so entry password will be set to the PKCS #12 "dummy value" password
                    if (sCurrentType.equals(KeyStoreType.PKCS12.toString()))
                    {
                        // Warn the user about this
                        if (!bWarnPkcs12Password)
                        {
                            bWarnPkcs12Password = true;
                            JOptionPane.showMessageDialog(this, MessageFormat.format(m_res.getString("FKeyToolGUI.ChangeFromPkcs12Password.message"), new String[]{new String(PKCS12_DUMMY_PASSWORD)}),
                                                          m_res.getString("FKeyToolGUI.ChangeKeyStoreType.Title"),
                                                          JOptionPane.INFORMATION_MESSAGE);
                        }
                    }
                    // The new KeyStore type is PKCS #12 so use "dummy value" password for entry
                    else if (keyStoreType == KeyStoreType.PKCS12)
                    {
                        cPassword = PKCS12_DUMMY_PASSWORD;
                    }

                    // Put key and (possibly null) certificate chain in new KeyStore
                    newKeyStore.setKeyEntry(sAlias, key, cPassword, certificateChain);

                    // Update wrapper with password
                    m_keyStoreWrap.setEntryPassword(sAlias, cPassword);
                }
            }

            // Successful change of type - put new KeyStore into wrapper
            m_keyStoreWrap.setKeyStore(newKeyStore);
            m_keyStoreWrap.setChanged(true);

            // Update the frame's components and title
            updateControls();
            updateTitle();

            // Display success message
            JOptionPane.showMessageDialog(this, m_res.getString("FKeyToolGUI.ChangeKeyStoreTypeSuccessful.message"),
                                          m_res.getString("FKeyToolGUI.ChangeKeyStoreType.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);
            return true;
        }
        catch (Exception ex)
        {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user set the KeyStore's password.
     *
     * @return True if the password was set, false otherwise
     */
    private boolean setKeyStorePassword()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        char[] cPassword = getNewKeyStorePassword();

        // User cancelled
        if (cPassword == null)
        {
            return false;
        }

        // Update the KeyStore wrapper
        m_keyStoreWrap.setPassword(cPassword);
        m_keyStoreWrap.setChanged(true);

        // Update the frame's components and title
        updateControls();
        updateTitle();

        return true;
    }

    /**
     * Let the user set the password for the selected key pair entry.
     *
     * @return True if the password is set, false otherwise
     */
    private boolean setPasswordSelectedEntry()
    {
        assert m_keyStoreWrap.getKeyStore() != null;
        assert (!m_keyStoreWrap.getKeyStore().getType().equals(KeyStoreType.PKCS12.toString())); // Not relevant for a PKCS #12 KeyStore

        // What entry has been selected?
        int iRow = m_jtKeyStore.getSelectedRow();

        if (iRow == -1)
        {
            return false;
        }

        // Not valid for a key or trusted certificate entry
        if ((((String)m_jtKeyStore.getValueAt(iRow, 0)).equals(KeyStoreTableModel.KEY_ENTRY)) ||
            (((String)m_jtKeyStore.getValueAt(iRow, 0)).equals(KeyStoreTableModel.TRUST_CERT_ENTRY)))
        {
            return false;
        }

        // Get entry alias
        String sAlias = (String)m_jtKeyStore.getValueAt(iRow, 1);

        // Do we already know the current password for the entry?
        char[] cOldPassword = m_keyStoreWrap.getEntryPassword(sAlias);

        /* Display the change password dialog supplying the current password to
           it if it was available */
        DChangePassword dChangePassword = new DChangePassword(this, true, m_res.getString("FKeyToolGUI.SetKeyPairPassword.Title"), cOldPassword);
        dChangePassword.setLocationRelativeTo(this);
        dChangePassword.setVisible(true);

        // Get the password settings the user made in the dialog
        if (cOldPassword == null)
        {
            cOldPassword = dChangePassword.getOldPassword();
        }
        char[] cNewPassword = dChangePassword.getNewPassword();

        // Dialog was cancelled
        if ((cOldPassword == null) || (cNewPassword == null))
        {
            return false;
        }

        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        try
        {
            // Change the password by recreating the entry
            Certificate[] cert = keyStore.getCertificateChain(sAlias);
            Key key = keyStore.getKey(sAlias, cOldPassword);
            keyStore.deleteEntry(sAlias);
            keyStore.setKeyEntry(sAlias, key, cNewPassword, cert);

            // Update the KeyStore wrapper
            m_keyStoreWrap.setEntryPassword(sAlias, cNewPassword);
            m_keyStoreWrap.setChanged(true);
        }
        catch (GeneralSecurityException ex)
        {
            displayException(ex);
            return false;
        }

        // Update the frame's components and title
        updateControls();
        updateTitle();

        return true;
    }

    /**
     * Let the user export the selected entry.
     *
     * @return True if the export is successful, false otherwise
     */
    private boolean exportSelectedEntry()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // What entry has been selected?
        int iRow = m_jtKeyStore.getSelectedRow();

        if (iRow == -1)
        {
            return false;
        }

        // Not valid for a key entry
        if (((String)m_jtKeyStore.getValueAt(iRow, 0)).equals(KeyStoreTableModel.KEY_ENTRY))
        {
            return false;
        }

        // Get the entry
        String sAlias = (String)m_jtKeyStore.getValueAt(iRow, 1);

        try
        {
            /* Display the Generate Key Pair dialog to get the key pair generation
               parameters from the user */
            DExport dExport = new DExport(this, true, m_keyStoreWrap, sAlias, m_lastDir);
            dExport.setLocationRelativeTo(this);
            dExport.setVisible(true);

            if (!dExport.exportSelected())
            {
                return false; // User cancelled the dialog
            }

            // Do export
            boolean bSuccess = false;

            // Export head certificate only
            if (dExport.exportHead())
            {
                // Export PEM encoded format
                if (dExport.exportPem())
                {
                    bSuccess = exportHeadCertOnlyPem(sAlias);
                }
                // Export DER encoded format
                else if (dExport.exportDer())
                {
                    bSuccess = exportHeadCertOnlyDER(sAlias);
                }
                // Export PKCS #7 format
                else
                {
                   bSuccess = exportHeadCertOnlyPkcs7(sAlias);
                }
            }
            // Complete cert path (PKCS #7)
            else if (dExport.exportChain())
            {
                bSuccess = exportAllCertsPkcs7(sAlias);
            }
            // Complete cert path and private key (PKCS #12)
            else
            {
                bSuccess = exportPrivKeyCertChain(sAlias);
            }

			if (bSuccess)
			{
            	// Display success message
            	JOptionPane.showMessageDialog(this, m_res.getString("FKeyToolGUI.ExportSuccessful.message"),
            	                              m_res.getString("FKeyToolGUI.Export.Title"),
            	                              JOptionPane.INFORMATION_MESSAGE);
            }
        }
        catch (Exception ex)
        {
            displayException(ex);
            return false;
        }

        return true;
    }

    /**
     * Export the head certificate of the KeyStore entry in a PEM encoding.
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportHeadCertOnlyPem(String sEntryAlias)
    {
        // Let the user choose the export cert file
        File fExportFile = chooseExportCertFile();
        if (fExportFile == null)
        {
            return false;
        }

        // File already exists
        if (fExportFile.isFile())
        {
            String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.OverWriteFile.message"), new String[]{fExportFile.getName()});
            int iSelected = JOptionPane.showConfirmDialog(this, sMessage, getTitle(), JOptionPane.YES_NO_OPTION);
            if (iSelected == JOptionPane.NO_OPTION)
            {
                return false;
            }
        }

        try
        {
            // Get the head certificate
            X509Certificate cert = getHeadCert(sEntryAlias);

            // Do the export
            String sEncoded = X509CertUtil.getCertEncodedPem(cert);

            FileWriter fw = new FileWriter(fExportFile);
            fw.write(sEncoded);
            fw.close();

            m_lastDir.updateLastDir(fExportFile);

            return true;
        }
        catch (FileNotFoundException ex)
        {
            String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.NoWriteFile.message"), new String[]{fExportFile.getName()});
            JOptionPane.showMessageDialog(this, sMessage, getTitle(), JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (IOException ex)
        {
            displayException(ex);
            return false;
        }
        catch (CryptoException ex)
        {
            displayException(ex);
            return false;
        }
    }

    /**
     * Export the head certificate of the KeyStore entry in a DER encoding.
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportHeadCertOnlyDER(String sEntryAlias)
    {
        // Let the user choose the export cert file
        File fExportFile = chooseExportCertFile();
        if (fExportFile == null)
        {
            return false;
        }

        // File already exists
        if (fExportFile.isFile())
        {
            String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.OverWriteFile.message"), new String[]{fExportFile.getName()});
            int iSelected = JOptionPane.showConfirmDialog(this, sMessage, getTitle(), JOptionPane.YES_NO_OPTION);
            if (iSelected == JOptionPane.NO_OPTION)
            {
                return false;
            }
        }

        try
        {
            // Get the head certificate
            X509Certificate cert = getHeadCert(sEntryAlias);

            // Do the export
            byte[] bEncoded = X509CertUtil.getCertEncodedDer(cert);
            FileOutputStream fos = new FileOutputStream(fExportFile);
            fos.write(bEncoded);
            fos.close();

            m_lastDir.updateLastDir(fExportFile);

            return true;
        }
        catch (FileNotFoundException ex)
        {
            String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.NoWriteFile.message"), new String[]{fExportFile.getName()});
            JOptionPane.showMessageDialog(this, sMessage, getTitle(), JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (IOException ex)
        {
            displayException(ex);
            return false;
        }
        catch (CryptoException ex)
        {
            displayException(ex);
            return false;
        }
    }

    /**
     * Export the head certificate of the KeyStore entry to a PKCS #7 file.
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportHeadCertOnlyPkcs7(String sEntryAlias)
    {
        // Let the user choose the export PKCS #7 file
        File fExportFile = chooseExportPKCS7File();
        if (fExportFile == null)
        {
            return false;
        }

        // File already exists
        if (fExportFile.isFile())
        {
            String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.OverWriteFile.message"), new String[]{fExportFile.getName()});
            int iSelected = JOptionPane.showConfirmDialog(this, sMessage, getTitle(), JOptionPane.YES_NO_OPTION);
            if (iSelected == JOptionPane.NO_OPTION)
            {
                return false;
            }
        }

        try
        {
            // Get the head certificate
            X509Certificate cert = getHeadCert(sEntryAlias);

            // Do the export
            byte[] bEncoded = X509CertUtil.getCertEncodedPkcs7(cert);
            FileOutputStream fos = new FileOutputStream(fExportFile);
            fos.write(bEncoded);
            fos.close();

            m_lastDir.updateLastDir(fExportFile);

            return true;
        }
        catch (FileNotFoundException ex)
        {
            String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.NoWriteFile.message"), new String[]{fExportFile.getName()});
            JOptionPane.showMessageDialog(this, sMessage, getTitle(), JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (IOException ex)
        {
            displayException(ex);
            return false;
        }
        catch (CryptoException ex)
        {
            displayException(ex);
            return false;
        }
    }

    /**
     * Export all of the certificates of the KeyStore entry to a PKCS #7 file.
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportAllCertsPkcs7(String sEntryAlias)
    {
        // Let the user choose the export PKCS #7 file
        File fExportFile = chooseExportPKCS7File();
        if (fExportFile == null)
        {
            return false;
        }

        // File already exists
        if (fExportFile.isFile())
        {
            String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.OverWriteFile.message"), new String[]{fExportFile.getName()});
            int iSelected = JOptionPane.showConfirmDialog(this, sMessage, getTitle(), JOptionPane.YES_NO_OPTION);
            if (iSelected == JOptionPane.NO_OPTION)
            {
                return false;
            }
        }

        try
        {
            // Get the certificates
            KeyStore keyStore = m_keyStoreWrap.getKeyStore();
            X509Certificate[] certChain = X509CertUtil.convertCertificates(keyStore.getCertificateChain(sEntryAlias));

            // Do the export
            byte[] bEncoded = X509CertUtil.getCertsEncodedPkcs7(certChain);
            FileOutputStream fos = new FileOutputStream(fExportFile);
            fos.write(bEncoded);
            fos.close();

            m_lastDir.updateLastDir(fExportFile);

            return true;
        }
        catch (FileNotFoundException ex)
        {
            String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.NoWriteFile.message"), new String[]{fExportFile.getName()});
            JOptionPane.showMessageDialog(this, sMessage, getTitle(), JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (IOException ex)
        {
            displayException(ex);
            return false;
        }
        catch (KeyStoreException ex)
        {
            displayException(ex);
            return false;
        }
        catch (CryptoException ex)
        {
            displayException(ex);
            return false;
        }
    }

    /**
     * Get the KeyStore entry's head certificate.
     *
     * @param sEntryAlias Entry alias
     * @return The KeyStore entry's head certificate
     * @throws CryptoException Problem getting head certificate
     */
    private X509Certificate getHeadCert(String sEntryAlias) throws CryptoException
    {
        try
        {
            // Get KeyStore
            KeyStore keyStore = m_keyStoreWrap.getKeyStore();

            // Get the entry's head certificate
            X509Certificate cert;
            if (keyStore.isKeyEntry(sEntryAlias))
            {
                cert = X509CertUtil.orderX509CertChain(
                    X509CertUtil.convertCertificates(keyStore.getCertificateChain(sEntryAlias))
                )[0];
            }
            else
            {
                cert = X509CertUtil.convertCertificate(keyStore.getCertificate(sEntryAlias));
            }

            return cert;
        }
        catch (KeyStoreException ex)
        {
            String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.NoAccessEntry.message"), new String[]{sEntryAlias});
            throw new CryptoException(sMessage, ex);
        }
    }

   /**
     * Export the private key and certificates of the KeyStore entry to
     * a PKCS #12 KeyStore file.
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportPrivKeyCertChain(String sEntryAlias)
    {
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        // Get the entry's password (we may already know it from the wrapper)
        char[] cPassword = m_keyStoreWrap.getEntryPassword(sEntryAlias);

        if (cPassword == null)
        {
            cPassword = PKCS12_DUMMY_PASSWORD;

            // Password is only relevant if the KeyStore is not PKCS #12
            if (!keyStore.getType().equals(KeyStoreType.PKCS12.toString()))
            {
                DGetPassword dGetPassword = new DGetPassword(this,  m_res.getString("FKeyToolGUI.KeyEntryPassword.Title"), true);
                dGetPassword.setLocationRelativeTo(this);
                dGetPassword.setVisible(true);
                cPassword = dGetPassword.getPassword();

                if (cPassword == null)
                {
                    return false;
                }
            }
        }

        File fExportFile = null;

        try
        {
            // Get the private key and certificate chain from the entry
            Key privKey = keyStore.getKey(sEntryAlias, cPassword);
            Certificate[] certs = keyStore.getCertificateChain(sEntryAlias);

            // Update the KeyStore wrapper
            m_keyStoreWrap.setEntryPassword(sEntryAlias, cPassword);

            // Create a new PKCS #12 KeyStore
            KeyStore pkcs12 = KeyStoreUtil.createKeyStore(KeyStoreType.PKCS12);

            // Place the private key and certificate chain into the PKCS #12 KeyStore under
            // the same alias as it has in the loaded KeyStore
            pkcs12.setKeyEntry(sEntryAlias, privKey, new char[0], certs);

            // Get a new password for the PKCS #12 KeyStore
            DGetNewPassword dGetNewPassword = new DGetNewPassword(this, m_res.getString("FKeyToolGUI.Pkcs12Password.Title"), true);
            dGetNewPassword.setLocationRelativeTo(this);
            dGetNewPassword.setVisible(true);

            char[] cPKCS12Password = dGetNewPassword.getPassword();

            if (cPKCS12Password == null)
            {
                return false;
            }

            // Let the user choose the export PKCS #12 file
            fExportFile = chooseExportPKCS12File();
            if (fExportFile == null)
            {
                return false;
            }

            // File already exists
            if (fExportFile.isFile())
            {
                String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.OverWriteFile.message"), new String[]{fExportFile.getName()});
                int iSelected = JOptionPane.showConfirmDialog(this, sMessage, getTitle(), JOptionPane.YES_NO_OPTION);
                if (iSelected == JOptionPane.NO_OPTION)
                {
                    return false;
                }
            }

            // Store the KeyStore to disk
            KeyStoreUtil.saveKeyStore(pkcs12, fExportFile, cPKCS12Password);

            m_lastDir.updateLastDir(fExportFile);

            return true;
        }
        catch (FileNotFoundException ex)
        {
            String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.NoWriteFile.message"), new String[]{fExportFile.getName()});
            JOptionPane.showMessageDialog(this, sMessage, getTitle(), JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (IOException ex)
        {
            displayException(ex);
            return false;
        }
        catch (KeyStoreException ex)
        {
            displayException(ex);
            return false;
        }
        catch (NoSuchAlgorithmException ex)
        {
            displayException(ex);
            return false;
        }
        catch (UnrecoverableKeyException ex)
        {
            displayException(ex);
            return false;
        }
        catch (CryptoException ex)
        {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user choose a certificate file to export to.
     *
     * @return The chosen file or null if none was chosen
     */
    private File chooseExportCertFile()
    {
        JFileChooser chooser = FileChooserFactory.getX509FileChooser();

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null)
        {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FKeyToolGUI.ExportCertificate.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this, m_res.getString("FKeyToolGUI.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION)
        {
            File fExportFile = chooser.getSelectedFile();
            return fExportFile;
        }
        return null;
    }

   /**
     * Let the user choose a PKCS #7 file to export to.
     *
     * @return The chosen file or null if none was chosen
     */
    private File chooseExportPKCS7File()
    {
        JFileChooser chooser = FileChooserFactory.getPkcs7FileChooser();

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null)
        {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FKeyToolGUI.ExportCertificates.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this, m_res.getString("FKeyToolGUI.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION)
        {
            File fExportFile = chooser.getSelectedFile();
            return fExportFile;
        }
        return null;
    }

    /**
     * Let the user choose a PKCS #12 file to export to.
     *
     * @return The chosen file or null if none was chosen
     */
    private File chooseExportPKCS12File()
    {
        JFileChooser chooser = FileChooserFactory.getPkcs12FileChooser();

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null)
        {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FKeyToolGUI.ExportKeyCertificates.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this, m_res.getString("FKeyToolGUI.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION)
        {
            File fExportFile = chooser.getSelectedFile();
            return fExportFile;
        }
        return null;
    }

    /**
     * Let the user generate a CSR for the selected key pair entry.
     *
     * @return True if the generation is successful, false otherwise
     */
    private boolean generateCsrSelectedEntry()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // What entry is selected?
        int iRow = m_jtKeyStore.getSelectedRow();

        if (iRow == -1)
        {
            return false;
        }

        // Not valid for a key or trusted certificate entry
        if ((((String)m_jtKeyStore.getValueAt(iRow, 0)).equals(KeyStoreTableModel.KEY_ENTRY)) ||
            (((String)m_jtKeyStore.getValueAt(iRow, 0)).equals(KeyStoreTableModel.TRUST_CERT_ENTRY)))
        {
            return false;
        }

        String sAlias = (String)m_jtKeyStore.getValueAt(iRow, 1);
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        File fCsrFile = null;

        try
        {
            // Get the entry's password (we may already know it from the wrapper)
            char[] cPassword = m_keyStoreWrap.getEntryPassword(sAlias);

            if (cPassword == null)
            {
                cPassword = PKCS12_DUMMY_PASSWORD;

                // Password is only relevant if the KeyStore is not PKCS #12
                if (!keyStore.getType().equals(KeyStoreType.PKCS12.toString()))
                {
                    DGetPassword dGetPassword = new DGetPassword(this,  m_res.getString("FKeyToolGUI.KeyEntryPassword.Title"), true);
                    dGetPassword.setLocationRelativeTo(this);
                    dGetPassword.setVisible(true);
                    cPassword = dGetPassword.getPassword();

                    if (cPassword == null)
                    {
                        return false;
                    }
                }
            }

            // Get the key pair entry's private key using the password
            PrivateKey privKey = (PrivateKey)keyStore.getKey(sAlias, cPassword);

            // Update the KeyStore wrapper
            m_keyStoreWrap.setEntryPassword(sAlias, cPassword);

            // Let the user choose the file to write the CSR to
            fCsrFile = chooseGenerateCsrFile();
            if (fCsrFile == null)
            {
                return false;
            }

            // The chosen file already exists
            if (fCsrFile.isFile())
            {
                int iSelected = JOptionPane.showConfirmDialog(this, MessageFormat.format(m_res.getString("FKeyToolGUI.OverWriteFile.message"), new Object[]{fCsrFile}),
                                                              m_res.getString("FKeyToolGUI.GenerateCsr.Title"), JOptionPane.YES_NO_OPTION);
                if (iSelected == JOptionPane.NO_OPTION)
                {
                    return false;
                }
            }

            // Get the first certficate in the entry's certificate chain
            X509Certificate cert = X509CertUtil.orderX509CertChain(
                X509CertUtil.convertCertificates(keyStore.getCertificateChain(sAlias))
            )[0];

            // Generate the CSR using the entry's certficate and private key
            String sCsr = X509CertUtil.generatePKCS10CSR(cert, privKey);

            // Write it out to file
            FileWriter fw = new FileWriter(fCsrFile);
            fw.write(sCsr);
            fw.close();

            // Display success message
            JOptionPane.showMessageDialog(this, m_res.getString("FKeyToolGUI.CsrGenerationSuccessful.message"),
                                          m_res.getString("FKeyToolGUI.GenerateCsr.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);

            m_lastDir.updateLastDir(fCsrFile);

            return true;
        }
        catch (FileNotFoundException ex)
        {
            JOptionPane.showMessageDialog(this, MessageFormat.format(m_res.getString("FKeyToolGUI.NoWriteFile.message"), new Object[]{fCsrFile}),
                                          m_res.getString("FKeyToolGUI.GenerateCsr.Title"), JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (Exception ex)
        {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user clone the selected key pair entry.
     *
     * @return True if the clone is successful, false otherwise
     */
    private boolean cloneSelectedEntry()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // What entry has been selected?
        int iRow = m_jtKeyStore.getSelectedRow();

        if (iRow == -1)
        {
            return false;
        }

        // Not valid for a key or trusted certificate entry
        if ((((String)m_jtKeyStore.getValueAt(iRow, 0)).equals(KeyStoreTableModel.KEY_ENTRY)) ||
            (((String)m_jtKeyStore.getValueAt(iRow, 0)).equals(KeyStoreTableModel.TRUST_CERT_ENTRY)))
        {
            return false;
        }

        String sAlias = (String)m_jtKeyStore.getValueAt(iRow, 1);
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        try
        {
            // Get the entry's password (we may already know it from the wrapper)
            char[] cPassword = m_keyStoreWrap.getEntryPassword(sAlias);

            if (cPassword == null)
            {
                cPassword = PKCS12_DUMMY_PASSWORD;

                // Password is only relevant if the KeyStore is not PKCS #12
                if (!keyStore.getType().equals(KeyStoreType.PKCS12.toString()))
                {
                    DGetPassword dGetPassword = new DGetPassword(this,  m_res.getString("FKeyToolGUI.KeyEntryPassword.Title"), true);
                    dGetPassword.setLocationRelativeTo(this);
                    dGetPassword.setVisible(true);
                    cPassword = dGetPassword.getPassword();

                    if (cPassword == null)
                    {
                        return false;
                    }
                }
            }

            // Get private key and certificates from entry
            PrivateKey privKey = (PrivateKey)keyStore.getKey(sAlias, cPassword);
            Certificate[] certs = keyStore.getCertificateChain(sAlias);

            // Update the KeyStore wrapper
            m_keyStoreWrap.setEntryPassword(sAlias, cPassword);

            // Get the alias of the new entry
            X509Certificate[] x509Certs = X509CertUtil.orderX509CertChain(
                X509CertUtil.convertCertificates(certs)
            );

            DGetAlias dGetAlias = new DGetAlias(this, m_res.getString("FKeyToolGUI.ClonedKeyPairEntryAlias.Title"), true, X509CertUtil.getCertificateAlias(x509Certs[0]));
            dGetAlias.setLocationRelativeTo(this);
            dGetAlias.setVisible(true);
            String sNewAlias = dGetAlias.getAlias();

            if (sNewAlias == null)
            {
                return false;
            }

            // Check new alias differs from the present one
            if (sNewAlias.equalsIgnoreCase(sAlias))
            {
                JOptionPane.showMessageDialog(this, MessageFormat.format(m_res.getString("FKeyToolGUI.CloneAliasIdentical.message"), new String[]{sAlias}),
                                              m_res.getString("FKeyToolGUI.CloneEntry.Title"), JOptionPane.ERROR_MESSAGE);
                return false;
            }

            // Check entry does not already exist in the KeyStore
            if (keyStore.containsAlias(sNewAlias))
            {
                String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.OverwriteAlias.message"),
                                                       new String[]{sNewAlias});

                int iSelected = JOptionPane.showConfirmDialog(this, sMessage, m_res.getString("FKeyToolGUI.ClonedKeyPairEntryAlias.Title"),
                                                              JOptionPane.YES_NO_CANCEL_OPTION);
                if (iSelected == JOptionPane.CANCEL_OPTION)
                {
                    return false;
                }
                else if (iSelected == JOptionPane.NO_OPTION)
                {
                    return false;
                }
                // Otherwise carry on - delete entry to be copied over
                keyStore.deleteEntry(sNewAlias);
            }

            // Get a password for the new KeyStore entry (only relevant if the KeyStore is not PKCS #12)
            char[] cNewPassword = PKCS12_DUMMY_PASSWORD;

            if (!keyStore.getType().equals(KeyStoreType.PKCS12.toString()))
            {
                DGetNewPassword dGetNewPassword = new DGetNewPassword(this, m_res.getString("FKeyToolGUI.ClonedKeyPairEntryPassword.Title"), true);
                dGetNewPassword.setLocationRelativeTo(this);
                dGetNewPassword.setVisible(true);
                cNewPassword = dGetNewPassword.getPassword();

                if (cNewPassword == null)
                {
                    return false;
                }
            }

            // Create new entry
            keyStore.setKeyEntry(sNewAlias, privKey, cNewPassword, certs);

            // Update the KeyStore wrapper
            m_keyStoreWrap.setEntryPassword(sNewAlias, cNewPassword);
            m_keyStoreWrap.setChanged(true);

            // ...and update the frame's components and title
            updateControls();
            updateTitle();

            // Display success message
            JOptionPane.showMessageDialog(this, m_res.getString("FKeyToolGUI.KeyPairCloningSuccessful.message"),
                                          m_res.getString("FKeyToolGUI.CloneKeyPair.Title"),
                                          JOptionPane.INFORMATION_MESSAGE);

            return true;
        }
        catch (Exception ex)
        {
            displayException(ex);
            return false;
        }
    }

    /**
     * Display a report on the currently loaded KeyStore.
     *
     * @return True if the KeyStore report was displayed successfully, false otherwise
     */
    private boolean keyStoreReport()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        try
        {
            DKeyStoreReport dKeyStoreReport = new DKeyStoreReport(this, true, m_keyStoreWrap.getKeyStore());
            dKeyStoreReport.setLocationRelativeTo(this);
            dKeyStoreReport.setVisible(true);
            return true;
        }
        catch (Exception ex)
        {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user see the certificate details of the selected KeyStore entry.
     *
     * @return True if the certificate details were viewed suceesfully, false otherwise
     */
    private boolean showSelectedEntry()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // What entry has been selected?
        int iRow = m_jtKeyStore.getSelectedRow();

        if (iRow == -1)
        {
            return false;
        }

        // Not valid for a key entry
        if (((String)m_jtKeyStore.getValueAt(iRow, 0)).equals(KeyStoreTableModel.KEY_ENTRY))
        {
            return false;
        }

        String sAlias = (String)m_jtKeyStore.getValueAt(iRow, 1);
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        try
        {
            // Get the entry's certificates
            X509Certificate[] certs;
            if (keyStore.isKeyEntry(sAlias))
            {
                // If entry is a key pair
                certs = X509CertUtil.convertCertificates(keyStore.getCertificateChain(sAlias));
            }
            else
            {
                // If entry is a trusted certificate
                certs = new X509Certificate[1];
                certs[0] = X509CertUtil.convertCertificate(keyStore.getCertificate(sAlias));
            }

            // Supply the certificates to the view certificate dialog
            DViewCertificate dViewCertificate =
                new DViewCertificate(this, MessageFormat.format(m_res.getString("FKeyToolGUI.CertDetailsEntry.Title"), new String[]{sAlias}),
                                     true, certs);
            dViewCertificate.setLocationRelativeTo(this);
            dViewCertificate.setVisible(true);
            return true;
        }
        catch (Exception ex)
        {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user delete the selected KeyStore entry.
     *
     * @return True if the deletion is successful, false otherwise
     */
    private boolean deleteSelectedEntry()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // What entry has been selected?
        int iRow = m_jtKeyStore.getSelectedRow();

        if (iRow == -1)
        {
            return false;
        }

        // Not valid for a key entry
        if (((String)m_jtKeyStore.getValueAt(iRow, 0)).equals(KeyStoreTableModel.KEY_ENTRY))
        {
            return false;
        }

        String sAlias = (String)m_jtKeyStore.getValueAt(iRow, 1);
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        try
        {
            // Delete the entry
            keyStore.deleteEntry(sAlias);

            // Update the KeyStore wrapper
            m_keyStoreWrap.removeEntryPassword(sAlias);
            m_keyStoreWrap.setChanged(true);
        }
        catch (KeyStoreException ex)
        {
            displayException(ex);
            return false;
        }

        // Update the frame's components and title
        updateControls();
        updateTitle();

        return true;
    }

    /**
     * Let the user rename the selected KeyStore entry.
     *
     * @return True if the rename is successful, false otherwise
     */
    private boolean renameSelectedEntry()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // What entry has been selected?
        int iRow = m_jtKeyStore.getSelectedRow();

        if (iRow == -1)
        {
            return false;
        }

        // Not valid for a key entry
        if (((String)m_jtKeyStore.getValueAt(iRow, 0)).equals(KeyStoreTableModel.KEY_ENTRY))
        {
            return false;
        }

        String sAlias = (String)m_jtKeyStore.getValueAt(iRow, 1);
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        try
        {
            // Get the new entry alias
            DGetAlias dGetAlias = new DGetAlias(this, m_res.getString("FKeyToolGUI.NewEntryAlias.Title"), true, sAlias);
            dGetAlias.setLocationRelativeTo(this);
            dGetAlias.setVisible(true);
            String sNewAlias = dGetAlias.getAlias();

            if (sNewAlias == null)
            {
                return false;
            }

            // Check new alias differs from the present one
            if (sNewAlias.equalsIgnoreCase(sAlias))
            {
                JOptionPane.showMessageDialog(this, MessageFormat.format(m_res.getString("FKeyToolGUI.RenameAliasIdentical.message"), new String[]{sAlias}),
                                              m_res.getString("FKeyToolGUI.RenameEntry.Title"), JOptionPane.ERROR_MESSAGE);
                return false;
            }

            // Check entry does not already exist in the KeyStore
            if (keyStore.containsAlias(sNewAlias))
            {
                String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.OverWriteEntry.message"), new String[]{sNewAlias});

                int iSelected = JOptionPane.showConfirmDialog(this, sMessage,
                                                              m_res.getString("FKeyToolGUI.RenameEntry.Title"),
                                                              JOptionPane.YES_NO_OPTION);
                if (iSelected == JOptionPane.NO_OPTION)
                {
                    return false;
                }
            }

            // Create the new entry with the new name and copy the old entry across

            // If the entry is a key pair...
            if (keyStore.isKeyEntry(sAlias))
            {
                // Get the entry's password (we may already know it from the wrapper)
                char[] cPassword = m_keyStoreWrap.getEntryPassword(sAlias);

                if (cPassword == null)
                {
                    cPassword = PKCS12_DUMMY_PASSWORD;

                    // Password is only relevant if the KeyStore is not PKCS #12
                    if (!keyStore.getType().equals(KeyStoreType.PKCS12.toString()))
                    {
                        DGetPassword dGetPassword = new DGetPassword(this,  m_res.getString("FKeyToolGUI.KeyEntryPassword.Title"), true);
                        dGetPassword.setLocationRelativeTo(this);
                        dGetPassword.setVisible(true);
                        cPassword = dGetPassword.getPassword();

                        if (cPassword == null)
                        {
                            return false;
                        }
                    }
                }

                // Do the copy
                Key key = keyStore.getKey(sAlias, cPassword);
                Certificate[] certs = keyStore.getCertificateChain(sAlias);
                keyStore.setKeyEntry(sNewAlias, key, cPassword, certs);

                // Update the KeyStore wrapper
                m_keyStoreWrap.setEntryPassword(sNewAlias, cPassword);
            }
            // ...if the entry is a trusted certificate
            else
            {
                // Do the copy
                Certificate cert = keyStore.getCertificate(sAlias);
                keyStore.setCertificateEntry(sNewAlias, cert);
            }

            // Delete the old entry
            keyStore.deleteEntry(sAlias);

            // Update the KeyStore wrapper
            m_keyStoreWrap.removeEntryPassword(sAlias);
            m_keyStoreWrap.setChanged(true);
        }
        catch (Exception ex)
        {
            displayException(ex);
            return false;
        }

        // Update the frame's components and title
        updateControls();
        updateTitle();

        return true;
    }

    /**
     * Update the application's controls dependant on the state of its KeyStore
     * (eg if changes to KeyStore are saved disable save toolbar button).
     */
    private void updateControls()
    {
        // KeyStore must have been loaded
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // Has KeyStore been saved?
        if (m_keyStoreWrap.isChanged())
        {
            // No
            m_saveKeyStoreAction.setEnabled(true);
        }
        else
        {
            // Yes
            m_saveKeyStoreAction.setEnabled(false);
        }

        m_jmiSaveKeyStoreAs.setEnabled(true);

        m_genKeyPairAction.setEnabled(true);
        m_importTrustCertAction.setEnabled(true);
        m_importKeyPairAction.setEnabled(true);
        m_setKeyStorePassAction.setEnabled(true);
        m_keyStoreReportAction.setEnabled(true);

        // Show default status bar display
        setDefaultStatusBarText();

        // Get KeyStore
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        try
        {
            // Update KeyStore entries table
            ((KeyStoreTableModel)m_jtKeyStore.getModel()).load(m_keyStoreWrap.getKeyStore());
        }
        catch (KeyStoreException ex)
        {
            displayException(ex);
        }

        // Passwords are not relevant for PKCS #12 KeyStores
        if (keyStore.getType().equals(KeyStoreType.PKCS12.toString()))
        {
            m_jmiSetKeyPairPass.setEnabled(false);
        }
        else
        {
            m_jmiSetKeyPairPass.setEnabled(true);
        }

        // Change KeyStore type menu items dependant on KeyStore type

        // Enable change KeyStore type menu
        m_jmChangeKeyStoreType.setEnabled(true);

        // Initially enable the menu items for all types
        m_jmiChangeKeyStoreTypeJks.setEnabled(true);
        m_jmiChangeKeyStoreTypeJceks.setEnabled(true);
        m_jmiChangeKeyStoreTypePkcs12.setEnabled(true);
        m_jmiChangeKeyStoreTypeBks.setEnabled(true);
        m_jmiChangeKeyStoreTypeUber.setEnabled(true);

        // Disable the menu item matching current KeyStore type
        String sType = keyStore.getType();

        if (sType.equals(KeyStoreType.JKS.toString()))
        {
            m_jmiChangeKeyStoreTypeJks.setEnabled(false);
        }
        else if (sType.equals(KeyStoreType.JCEKS.toString()))
        {
            m_jmiChangeKeyStoreTypeJceks.setEnabled(false);
        }
        else if (sType.equals(KeyStoreType.PKCS12.toString()))
        {
            m_jmiChangeKeyStoreTypePkcs12.setEnabled(false);
        }
        else if (sType.equals(KeyStoreType.BKS.toString()))
        {
            m_jmiChangeKeyStoreTypeBks.setEnabled(false);
        }
        else if (sType.equals(KeyStoreType.UBER.toString()))
        {
            m_jmiChangeKeyStoreTypeUber.setEnabled(false);
        }
    }

    /**
     * Update the application's controls dependant on the state of its KeyStore.
     */
    private void updateTitle()
    {
        // Application name
        String sAppName = m_res.getString("FKeyToolGUI.Title");

        // No keystore loaded so just display the application name
        if (m_keyStoreWrap == null)
        {
            setTitle(sAppName);
        }
        else
        {
            File fKeyStore = m_keyStoreWrap.getKeyStoreFile();

            // A newly created keystore is loaded - display app name and Untitled string
            if (fKeyStore == null)
            {
                 setTitle(MessageFormat.format("{0} - [{1}]", new Object[]{sAppName, m_res.getString("FKeyToolGUI.Untitled")}));
            }
            else
            {
                // Unsaved KeyStore loaded - display app name, keystore file path and '*'
                if (m_keyStoreWrap.isChanged())
                {
                    setTitle(MessageFormat.format("{0} - [{1} *]", new Object[]{sAppName, fKeyStore}));
                }
                // Saved KeyStore loaded - display app name, keystore file path
                else
                {
                    setTitle(MessageFormat.format("{0} - [{1}]", new Object[]{sAppName, fKeyStore}));
                }
            }
        }
    }

    /**
     * Display the supplied text in the status bar.
     *
     * @param sStatus Text to display
     */
    public void setStatusBarText(String sStatus)
    {
        m_jlStatusBar.setText(sStatus);
    }

    /**
     * Set the text in the staus bar to reflect the status of the currently loaded KeyStore.
     */
    public void setDefaultStatusBarText()
    {
        // No KeyStore loaded...
        if (m_keyStoreWrap == null)
        {
            setStatusBarText(m_res.getString("FKeyToolGUI.noKeyStore.statusbar"));
        }
        // KeyStore loaded...
        else
        {
            // Get the KeyStore and display information on its type and size
            KeyStore ksLoaded = m_keyStoreWrap.getKeyStore();

            int iSize;
            try
            {
                iSize = ksLoaded.size();
            }
            catch (KeyStoreException ex)
            {
                setStatusBarText("");
                displayException(ex);
                return;
            }

            String sType = ksLoaded.getType();

            // If type is "PKCS12" use the more friendly type name "PKCS #12"
            if (sType.equals(KeyStoreType.PKCS12.toString()))
            {
                sType = "PKCS #12";
            }

            if (iSize == 1)
            {
                setStatusBarText(MessageFormat.format(m_res.getString("FKeyToolGUI.entry.statusbar"), new String[]{sType}));
            }
            else
            {
                setStatusBarText(MessageFormat.format(m_res.getString("FKeyToolGUI.entries.statusbar"), new String[]{sType, ""+iSize}));
            }
        }
    }

    /**
     * Save the application properties to file.
     */
    private void saveAppProps()
    {
        try
        {
            // Create properties
            Properties applicationProps = new Properties();

            // The size of the KeyStore table panel - determines the size of the main frame
            applicationProps.setProperty(m_res.getString("AppProps.Property.TableWidth"), Integer.toString(m_jpKeyStoreTable.getWidth()));
            applicationProps.setProperty(m_res.getString("AppProps.Property.TableHeight"), Integer.toString(m_jpKeyStoreTable.getHeight()));

            // The size of the KeyStore table's alias column - determines the size of all of the table's columns
            applicationProps.setProperty(m_res.getString("AppProps.Property.AliasWidth"), Integer.toString(m_jtKeyStore.getColumnModel().getColumn(1).getWidth()));

            // Application's position on the desktop
            applicationProps.setProperty(m_res.getString("AppProps.Property.XPos"), Integer.toString(this.getX()));
            applicationProps.setProperty(m_res.getString("AppProps.Property.YPos"), Integer.toString(this.getY()));

            // Use CA certificates file?
            applicationProps.setProperty(m_res.getString("AppProps.Property.UseCaCerts"), Boolean.toString(m_bUseCaCerts));

            // CA Certificates file
            applicationProps.setProperty(m_res.getString("AppProps.Property.CaCertsFile"), m_fCaCertsFile.toString());

            // Recent files
            File[] fRecentFiles = m_jmrfFile.getRecentFiles();
            for (int iCnt=0; iCnt < fRecentFiles.length; iCnt++)
            {
                applicationProps.setProperty(m_res.getString("AppProps.Property.RecentFile")+(iCnt+1), fRecentFiles[iCnt].toString());
            }

            // Look & feel
            LookAndFeel currentLookAndFeel = UIManager.getLookAndFeel();

            if (m_lookFeelOptions != null)
            {
				// Setting made in options
				applicationProps.setProperty(m_res.getString("AppProps.Property.LookFeel"), m_lookFeelOptions.getClassName());
			}
			else
			{
            	// Current setting
				if (currentLookAndFeel != null)
				{
					UIManager.LookAndFeelInfo[] lookFeelInfos = UIManager.getInstalledLookAndFeels();

					for (int iCnt=0; iCnt < lookFeelInfos.length; iCnt++)
					{
						UIManager.LookAndFeelInfo lookFeelInfo = lookFeelInfos[iCnt];

						// Store current look & feel class name
						if ((currentLookAndFeel != null) && (currentLookAndFeel.getName().equals(lookFeelInfo.getName())))
						{
							applicationProps.setProperty(m_res.getString("AppProps.Property.LookFeel"), lookFeelInfo.getClassName());
							break;
						}
					}
				}
			}


            // Use Look & Feel's decoration?
            if (m_bLookFeelDecorationOptions != null)
            {
				// Setting made in options
				applicationProps.setProperty(m_res.getString("AppProps.Property.LookFeelDecor"), m_bLookFeelDecorationOptions.toString());
			}
			else
			{
				// Current setting
            	applicationProps.setProperty(m_res.getString("AppProps.Property.LookFeelDecor"), Boolean.toString(JFrame.isDefaultLookAndFeelDecorated()));
			}

            // Do the save
            String sUserDir = System.getProperty("user.home");
            FileOutputStream fos = new FileOutputStream(new File(sUserDir, m_res.getString("AppProps.Filename")));
            applicationProps.store(fos, m_res.getString("AppProps.Header"));
            fos.close();
        }
        catch (Exception ex)
        {
            displayException(ex);
        }
    }

    /**
     * Load the application's properties from file.
     *
     * @return The application's properties
     */
    private static Properties loadAppProps()
    {
        // Get default properties
        Properties defaultAppProps = getDefaultAppProps();

        // Create application properties using defaults
        Properties appProps = new Properties(defaultAppProps);

        try
        {
            // Load application properties from file
            String sUserDir = System.getProperty("user.home");
            FileInputStream fis = new FileInputStream(new File(sUserDir, m_res.getString("AppProps.Filename")));
            appProps.load(fis);
            fis.close();
        }
        catch (IOException ex)
        {
            // Ignore - application properties file does not exist but we have defaults
        }

        return appProps;
    }

    /**
     * Get the application's default properties.
     *
     * @return The application's default properties
     */
    private static Properties getDefaultAppProps()
    {
        Properties defaultAppProps = new Properties();

        defaultAppProps.setProperty(m_res.getString("AppProps.Property.UseCaCerts"), Boolean.toString(false));

        String sJavaInstallDir = System.getProperty("java.home");
        String sFileSep = System.getProperty("file.separator");
        defaultAppProps.setProperty(m_res.getString("AppProps.Property.CaCertsFile"),
                                    new File(sJavaInstallDir, "lib" + sFileSep +
                                             "security" + sFileSep + "cacerts").toString());

        defaultAppProps.setProperty(m_res.getString("AppProps.Property.LookFeel"), FKeyToolGUI.DEFAULT_LOOK_FEEL);
        defaultAppProps.setProperty(m_res.getString("AppProps.Property.LookFeelDecor"), Boolean.toString(false));

        return defaultAppProps;
    }

    /**
     * Check that a JRE with at least version 1.4.0 is being used.
     *
     * @return True if this is the case, false otherwise
     */
    private static boolean checkJRE()
    {
        // Get the current Java Runtime Environment version
        String sJreVersion = System.getProperty("java.version");

        assert sJreVersion != null;

        JavaVersion actualJreVersion = null;

        try
        {
            actualJreVersion = new JavaVersion(sJreVersion);
        }
        catch (VersionException ex)
        {
            // Could not parse JRE version
            String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.NoParseJreVersion.message"), new String[]{sJreVersion});
            System.err.println(sMessage);
            JOptionPane.showMessageDialog(new JFrame(), sMessage, m_res.getString("FKeyToolGUI.Title"), JOptionPane.ERROR_MESSAGE);
            return false;
        }

        // Get the required Java Runtime Environment version
        JavaVersion reqJreVersion = null;

        try
        {
            reqJreVersion = new JavaVersion(REQ_JRE_VERSION);
        }
        catch (VersionException ex)
        {
            // Could not parse JRE version
            String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.NoParseJreVersion.message"), new String[]{sJreVersion});
            System.err.println(sMessage);
            JOptionPane.showMessageDialog(new JFrame(), sMessage, m_res.getString("FKeyToolGUI.Title"), JOptionPane.ERROR_MESSAGE);
            return false;
        }

        // JRE version < 1.4.0
        if (actualJreVersion.compareTo(reqJreVersion) < 0)
        {
            // It isn't - warn the user and exit
            String sMessage = MessageFormat.format(m_res.getString("FKeyToolGUI.MinJreVersionReq.message"), new Object[]{actualJreVersion, reqJreVersion});
            System.err.println(sMessage);
            JOptionPane.showMessageDialog(new JFrame(), sMessage,
                                          m_res.getString("FKeyToolGUI.Title"),
                                          JOptionPane.ERROR_MESSAGE);
            return false;
        }
        else
        {
            // JRE version => 1.4.0
            return true;
        }
    }

    /**
     * Exit the application.
     */
    private void exitApplication()
    {
        // Does the current KeyStore contain unsaved changes?
        if (needSave())
        {
            // Yes - ask the user if it should be saved
            int iWantSave = wantSave();

            if (iWantSave == JOptionPane.YES_OPTION)
            {
                // Save it
                saveKeyStore();
            }
            else if (iWantSave == JOptionPane.CANCEL_OPTION)
            {
				// May be exiting because of L&F change
                m_lookFeelOptions = null;
                m_bLookFeelDecorationOptions = null;

                return;
            }
        }

        // Save application properties
        saveAppProps();

        System.exit(0);
    }

    /**
     * Initialise the application's look and feel from application properties.
     *
     * @param appProps Application properties
     */
    private static void initLookAndFeel(Properties appProps)
    {
        /* Set the theme used by the Metal look and feel to be "Light Metal" -
           this gets rid of the naff bold text used by the default Metal theme */
        MetalLookAndFeel.setCurrentTheme(new LightMetalTheme());

        // Install extra look and feels (which may or may not be present)
        installLookFeel("net.sourceforge.mlf.metouia.MetouiaLookAndFeel");
        installLookFeel("com.incors.plaf.kunststoff.KunststoffLookAndFeel");
        installLookFeel("org.gtk.java.swing.plaf.gtk.GtkLookAndFeel");

        // Set look & feel using value from properties
        String sLookFeelClassName = appProps.getProperty(m_res.getString("AppProps.Property.LookFeel"));

        try
        {
            // Use the look and feel
            UIManager.setLookAndFeel(sLookFeelClassName);
        }
        // Didn't work - no matter
        catch (UnsupportedLookAndFeelException e) { }
        catch (ClassNotFoundException e) { }
        catch (InstantiationException e) { }
        catch (IllegalAccessException e) { }

        // Use look & feel's decoration?
        boolean bLookFeelDecorated = new Boolean(appProps.getProperty(m_res.getString("AppProps.Property.LookFeelDecor"))).booleanValue();

        JFrame.setDefaultLookAndFeelDecorated(bLookFeelDecorated);
        JDialog.setDefaultLookAndFeelDecorated(bLookFeelDecorated);
    }

    /**
     * Install the look and feel represented by the supplied class.
     *
     * @param sLookFeelClassName Name of look and feel class to install
     */
    private static void installLookFeel(String sLookFeelClassName)
    {
        // Install extra look and feel (if the class is present)
        try
        {
            // Get the name of the Look and Feel by instantiating an instance of the class
            Class lookFeelClass = Class.forName(sLookFeelClassName);
            Constructor lookFeelConstructor = lookFeelClass.getConstructor(new Class[]{});
            LookAndFeel lookAndFeel = (LookAndFeel)lookFeelConstructor.newInstance(new Object[]{});

            // Install Look and Feel
            UIManager.installLookAndFeel(lookAndFeel.getName(), sLookFeelClassName);
        }
        catch (ClassNotFoundException e) {}
        catch (NoSuchMethodException e) {}
        catch (InstantiationException e) {}
        catch (IllegalAccessException e) {}
        catch (InvocationTargetException  e) {}
    }

    /**
     * Display an exception.
     *
     * @param exception Exception to display
     */
    private void displayException(Exception exception)
    {
        DThrowable dThrowable = new DThrowable(this, true, exception);
        dThrowable.setLocationRelativeTo(this);
        dThrowable.setVisible(true);
    }

    /**
     * Set cursor to busy and disable application input.
     * This can be reversed by a subsequent call to setCursorFree.
     */
    private void setCursorBusy()
    {
        // Block all mouse events using glass pane
        Component glassPane = getRootPane().getGlassPane();
        glassPane.addMouseListener(new MouseAdapter(){});
        glassPane.setVisible(true);

        // Set cursor to busy
        glassPane.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
    }

    /**
     * Set cursor to free and enable application input.
     * Called after a call to setCursorBusy.
     */
    private void setCursorFree()
    {
        // Accept mouse events
        Component glassPane = getRootPane().getGlassPane();
        glassPane.setVisible(false);

        // Revert cursor to default
        glassPane.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
    }

    /**
     * Action to create a new KeyStore.
     */
    private class NewKeyStoreAction extends AbstractAction
    {
        /**
         * Construct action.
         */
        public NewKeyStoreAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString("FKeyToolGUI.NewKeyStoreAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION, m_res.getString("FKeyToolGUI.NewKeyStoreAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString("FKeyToolGUI.NewKeyStoreAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FKeyToolGUI.NewKeyStoreAction.text"));
            putValue(SHORT_DESCRIPTION, m_res.getString("FKeyToolGUI.NewKeyStoreAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.NewKeyStoreAction.image")))));
            setEnabled(true);
        }

        /**
         * Perform action.
         *
         * @param evt Action event
         */
        public void actionPerformed(ActionEvent evt)
        {
            setDefaultStatusBarText();
            setCursorBusy();
            repaint();

            Thread t = new Thread(new Runnable() {
                public void run()
                {
                    try { newKeyStore(); } finally { setCursorFree(); }
                }
            });
            t.start();
        }
    }

    /**
     * Action to save a KeyStore.
     */
    private class SaveKeyStoreAction extends AbstractAction
    {
        /**
         * Construct action.
         */
        public SaveKeyStoreAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString("FKeyToolGUI.SaveKeyStoreAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION, m_res.getString("FKeyToolGUI.SaveKeyStoreAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString("FKeyToolGUI.SaveKeyStoreAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FKeyToolGUI.SaveKeyStoreAction.text"));
            putValue(SHORT_DESCRIPTION, m_res.getString("FKeyToolGUI.SaveKeyStoreAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.SaveKeyStoreAction.image")))));
            setEnabled(false);
        }

        /**
         * Perform action.
         *
         * @param evt Action event
         */
        public void actionPerformed(ActionEvent evt)
        {
            setDefaultStatusBarText();
            setCursorBusy();
            repaint();

            Thread t = new Thread(new Runnable() {
                public void run()
                {
                    try { saveKeyStore(); } finally { setCursorFree(); }
                }
            });
            t.start();
        }
    }

    /**
     * Action to open a KeyStore.
     */
    private class OpenKeyStoreAction extends AbstractAction
    {
        /**
         * Construct action.
         */
        public OpenKeyStoreAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString("FKeyToolGUI.OpenKeyStoreAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION, m_res.getString("FKeyToolGUI.OpenKeyStoreAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString("FKeyToolGUI.OpenKeyStoreAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FKeyToolGUI.OpenKeyStoreAction.text"));
            putValue(SHORT_DESCRIPTION, m_res.getString("FKeyToolGUI.OpenKeyStoreAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.OpenKeyStoreAction.image")))));
            setEnabled(true);
        }

        /**
         * Perform action.
         *
         * @param evt Action event
         */
        public void actionPerformed(ActionEvent evt)
        {
            setDefaultStatusBarText();
            setCursorBusy();
            repaint();

            Thread t = new Thread(new Runnable() {
                public void run()
                {
                    try { openKeyStore(); } finally { setCursorFree(); }
                }
            });
            t.start();
        }
    }

    /**
     * Action to generate a KayPair.
     */
    private class GenKeyPairAction extends AbstractAction
    {
        /**
         * Construct action.
         */
        public GenKeyPairAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString("FKeyToolGUI.GenKeyPairAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION, m_res.getString("FKeyToolGUI.GenKeyPairAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString("FKeyToolGUI.GenKeyPairAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FKeyToolGUI.GenKeyPairAction.text"));
            putValue(SHORT_DESCRIPTION, m_res.getString("FKeyToolGUI.GenKeyPairAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.GenKeyPairAction.image")))));
            setEnabled(false);
        }

        /**
         * Perform action.
         *
         * @param evt Action event
         */
        public void actionPerformed(ActionEvent evt)
        {
            setDefaultStatusBarText();
            setCursorBusy();
            repaint();

            Thread t = new Thread(new Runnable() {
                public void run()
                {
                    try { generateKeyPair(); } finally { setCursorFree(); }
                }
            });
            t.start();
        }
    }

    /**
     * Action to import a trusted certificate.
     */
    private class ImportTrustCertAction extends AbstractAction
    {
        /**
         * Construct action.
         */
        public ImportTrustCertAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString("FKeyToolGUI.ImportTrustCertAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION, m_res.getString("FKeyToolGUI.ImportTrustCertAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString("FKeyToolGUI.ImportTrustCertAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FKeyToolGUI.ImportTrustCertAction.text"));
            putValue(SHORT_DESCRIPTION, m_res.getString("FKeyToolGUI.ImportTrustCertAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.ImportTrustCertAction.image")))));
            setEnabled(false);
        }

        /**
         * Perform action.
         *
         * @param evt Action event
         */
        public void actionPerformed(ActionEvent evt)
        {
            setDefaultStatusBarText();
            setCursorBusy();
            repaint();

            Thread t = new Thread(new Runnable() {
                public void run()
                {
                    try { importTrustedCert(); } finally { setCursorFree(); }
                }
            });
            t.start();
        }
    }

    /**
     * Action to import a KeyPair.
     */
    private class ImportKeyPairAction extends AbstractAction
    {
        /**
         * Construct action.
         */
        public ImportKeyPairAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString("FKeyToolGUI.ImportKeyPairAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION, m_res.getString("FKeyToolGUI.ImportKeyPairAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString("FKeyToolGUI.ImportKeyPairAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FKeyToolGUI.ImportKeyPairAction.text"));
            putValue(SHORT_DESCRIPTION, m_res.getString("FKeyToolGUI.ImportKeyPairAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.ImportKeyPairAction.image")))));
            setEnabled(false);
        }

        /**
         * Perform action.
         *
         * @param evt Action event
         */
        public void actionPerformed(ActionEvent evt)
        {
            setDefaultStatusBarText();
            setCursorBusy();
            repaint();

            Thread t = new Thread(new Runnable() {
                public void run()
                {
                    try { importKeyPair(); } finally { setCursorFree(); }
                }
            });
            t.start();
        }
    }

    /**
     * Action to set a KeyStore password.
     */
    private class SetKeyStorePassAction extends AbstractAction
    {
        /**
         * Construct action.
         */
        public SetKeyStorePassAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString("FKeyToolGUI.SetKeyStorePassAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION, m_res.getString("FKeyToolGUI.SetKeyStorePassAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString("FKeyToolGUI.SetKeyStorePassAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FKeyToolGUI.SetKeyStorePassAction.text"));
            putValue(SHORT_DESCRIPTION, m_res.getString("FKeyToolGUI.SetKeyStorePassAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.SetKeyStorePassAction.image")))));
            setEnabled(false);
        }

        /**
         * Perform action.
         *
         * @param evt Action event
         */
        public void actionPerformed(ActionEvent evt)
        {
            setDefaultStatusBarText();
            setCursorBusy();
            repaint();

            Thread t = new Thread(new Runnable() {
                public void run()
                {
                    try { setKeyStorePassword(); } finally { setCursorFree(); }
                }
            });
            t.start();
        }
    }

    /**
     * Action to show a KeyStore Report.
     */
    private class KeyStoreReportAction extends AbstractAction
    {
        /**
         * Construct action.
         */
        public KeyStoreReportAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString("FKeyToolGUI.KeyStoreReportAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION, m_res.getString("FKeyToolGUI.KeyStoreReportAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString("FKeyToolGUI.KeyStoreReportAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FKeyToolGUI.KeyStoreReportAction.text"));
            putValue(SHORT_DESCRIPTION, m_res.getString("FKeyToolGUI.KeyStoreReportAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.KeyStoreReportAction.image")))));
            setEnabled(false);
        }

        /**
         * Perform action.
         *
         * @param evt Action event
         */
        public void actionPerformed(ActionEvent evt)
        {
            setDefaultStatusBarText();
            setCursorBusy();
            repaint();

            Thread t = new Thread(new Runnable() {
                public void run()
                {
                    try { keyStoreReport(); } finally { setCursorFree(); }
                }
            });
            t.start();
        }
    }

    /**
     * Action to examine a certificate.
     */
    private class ExamineCertAction extends AbstractAction
    {
        /**
         * Construct action.
         */
        public ExamineCertAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString("FKeyToolGUI.ExamineCertAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION, m_res.getString("FKeyToolGUI.ExamineCertAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString("FKeyToolGUI.ExamineCertAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FKeyToolGUI.ExamineCertAction.text"));
            putValue(SHORT_DESCRIPTION, m_res.getString("FKeyToolGUI.ExamineCertAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.ExamineCertAction.image")))));
            setEnabled(true);
        }

        /**
         * Perform action.
         *
         * @param evt Action event
         */
        public void actionPerformed(ActionEvent evt)
        {
            setDefaultStatusBarText();
            setCursorBusy();
            repaint();

            Thread t = new Thread(new Runnable() {
                public void run()
                {
                    try { examineCert(); } finally { setCursorFree(); }
                }
            });
            t.start();
        }
    }

    /**
     * Action to examine a CRL.
     */
    private class ExamineCrlAction extends AbstractAction
    {
        /**
         * Construct action.
         */
        public ExamineCrlAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString("FKeyToolGUI.ExamineCrlAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION, m_res.getString("FKeyToolGUI.ExamineCrlAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString("FKeyToolGUI.ExamineCrlAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FKeyToolGUI.ExamineCrlAction.text"));
            putValue(SHORT_DESCRIPTION, m_res.getString("FKeyToolGUI.ExamineCrlAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.ExamineCrlAction.image")))));
            setEnabled(true);
        }

        /**
         * Perform action.
         *
         * @param evt Action event
         */
        public void actionPerformed(ActionEvent evt)
        {
            setDefaultStatusBarText();
            setCursorBusy();
            repaint();

            Thread t = new Thread(new Runnable() {
                public void run()
                {
                    try { examineCRL(); } finally { setCursorFree(); }
                }
            });
            t.start();
        }
    }

    /**
     * Action to make a donation.
     */
    private class DonateAction extends AbstractAction
    {
        /**
         * Construct action.
         */
        public DonateAction()
        {
            putValue(LONG_DESCRIPTION, m_res.getString("FKeyToolGUI.DonateAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString("FKeyToolGUI.DonateAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FKeyToolGUI.DonateAction.text"));
            putValue(SHORT_DESCRIPTION, m_res.getString("FKeyToolGUI.DonateAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.DonateAction.image")))));
            setEnabled(true);
        }

        /**
         * Perform action.
         *
         * @param evt Action event
         */
        public void actionPerformed(ActionEvent evt)
        {
            setDefaultStatusBarText();
            setCursorBusy();
            repaint();

            Thread t = new Thread(new Runnable() {
                public void run()
                {
                    try { makeDonation(); } finally { setCursorFree(); }
                }
            });
            t.start();
        }
    }

    /**
     * Action to show help.
     */
    private class HelpAction extends AbstractAction
    {
        /**
         * Construct action.
         */
        public HelpAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(KeyEvent.VK_F1, 0));
            putValue(LONG_DESCRIPTION, m_res.getString("FKeyToolGUI.HelpAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString("FKeyToolGUI.HelpAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FKeyToolGUI.HelpAction.text"));
            putValue(SHORT_DESCRIPTION, m_res.getString("FKeyToolGUI.HelpAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FKeyToolGUI.HelpAction.image")))));
            setEnabled(true);
        }

        /**
         * Perform action.
         *
         * @param evt Action event
         */
        public void actionPerformed(ActionEvent evt)
        {
            setDefaultStatusBarText();
            setCursorBusy();
            repaint();

            Thread t = new Thread(new Runnable() {
                public void run()
                {
                    try { showHelp(); } finally { setCursorFree(); }
                }
            });
            t.start();
        }
    }

    /**
     * Runnable to create and show KeyTool GUI.
     */
    private static class CreateAndShowGui implements Runnable
    {
        /** KeyStore file to open initially */
        private File m_fKeyStore;

        /**
         * Construct CreateAndShowGui.
         *
         * @param fKeyStore KeyStore file to open initially (supply null if none)
         */
        public CreateAndShowGui(File fKeyStore)
        {
            m_fKeyStore = fKeyStore;
        }

        /**
         * Create and show KeyTool GUI.
         */
        public void run()
        {
            // Load application properties
            Properties appProps = loadAppProps();

            // Initialise look & feel
            initLookAndFeel(appProps);

            // Create the application's main frame
            FKeyToolGUI fKeyToolGui = new FKeyToolGUI(appProps);

            // Display the KeyTool GUI application
            fKeyToolGui.setVisible(true);

            // If KeyStore file is not null then attempt to open it
            if (m_fKeyStore != null)
            {
                fKeyToolGui.openKeyStore(m_fKeyStore);
            }
        }
    }

    /**
     * Start the KeyTool GUI application.  Takes one optional argument -
     * the location of a KeyStore file to open upon startup.
     *
     * @param args the command line arguments
     */
    public static void main(String args[])
    {
        // Check that the correct JRE is being used
        if (!checkJRE())
        {
            System.exit(1);
        }

        try
        {
            // Instantiate the BouncyCastle provider
            Class bcProvClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            Provider bcProv = (Provider)bcProvClass.newInstance();

            // Add BC as a security provider
            Security.addProvider(bcProv);
        }
        catch (Throwable thw)
        {
            // No sign of the provider - warn the user and exit
            System.err.println(m_res.getString("FKeyToolGUI.NoLoadBc.message"));
            thw.printStackTrace();
            JOptionPane.showMessageDialog(new JFrame(), m_res.getString("FKeyToolGUI.NoLoadBc.message"),
                                          m_res.getString("FKeyToolGUI.Title"),
                                          JOptionPane.ERROR_MESSAGE);
            System.exit(1);
        }

        // Create and display a splash screen
        WSplash wSplash = new WSplash(Toolkit.getDefaultToolkit().createImage(ClassLoader.getSystemResource(m_res.getString("FKeyToolGUI.Splash.image"))), 3000);

        // Wait for the splash screen to disappear
        while (wSplash.isVisible())
        {
            try
            {
                Thread.sleep(500);
            }
            catch (InterruptedException ex)
            {
                // Do nothing
            }
        }

        /* If arguments have been supplied treat the first one as a KeyStore file */
        File fKeyStore = null;
        if (args.length > 0)
        {
            fKeyStore = new File(args[0]);
        }

        // Create and show GUI on the event handler thread
        SwingUtilities.invokeLater(new CreateAndShowGui(fKeyStore));
    }
}
