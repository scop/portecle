/*
 * FPortecle.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004-2007 Ville Skyttä, ville.skytta@iki.fi
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
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Image;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Enumeration;
import java.util.ResourceBundle;
import java.util.prefs.Preferences;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import javax.swing.Action;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTable;
import javax.swing.JToolBar;
import javax.swing.KeyStroke;
import javax.swing.LookAndFeel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.WindowConstants;
import javax.swing.border.BevelBorder;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.plaf.metal.MetalLookAndFeel;
import javax.swing.table.TableColumn;

import net.sf.portecle.crypto.CryptoException;
import net.sf.portecle.crypto.KeyPairType;
import net.sf.portecle.crypto.KeyStoreType;
import net.sf.portecle.crypto.KeyStoreUtil;
import net.sf.portecle.crypto.ProviderUtil;
import net.sf.portecle.crypto.X509CertUtil;
import net.sf.portecle.gui.JMenuItemRecentFile;
import net.sf.portecle.gui.JMenuRecentFiles;
import net.sf.portecle.gui.LastDir;
import net.sf.portecle.gui.WSplash;
import net.sf.portecle.gui.about.DAbout;
import net.sf.portecle.gui.crypto.DProviderInfo;
import net.sf.portecle.gui.error.DThrowable;
import net.sf.portecle.gui.help.FHelp;
import net.sf.portecle.gui.jar.DJarInfo;
import net.sf.portecle.gui.password.DChangePassword;
import net.sf.portecle.gui.password.DGetNewPassword;
import net.sf.portecle.gui.password.DGetPassword;
import net.sf.portecle.gui.statusbar.StatusBar;
import net.sf.portecle.gui.statusbar.StatusBarChangeHandler;
import net.sf.portecle.gui.theme.LightMetalTheme;
import net.sf.portecle.version.JavaVersion;
import net.sf.portecle.version.VersionException;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;

import edu.stanford.ejalbert.BrowserLauncher;

/**
 * Start class and main frame of the keystore GUI application.
 */
public class FPortecle
    extends JFrame
    implements StatusBar
{
    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Application preferences */
    private static Preferences m_appPrefs = Preferences.userNodeForPackage(FPortecle.class);

    /** Whether to show the splash screen */
    private static boolean m_bSplashScreen;

    /** Minimum required JRE version */
    private static final String REQ_JRE_VERSION = "1.4.0";

    /** Minimum required BC version */
    private static final Double REQ_BC_VERSION = new Double(1.38);

    /** Enable experimental features? */
    private static final boolean EXPERIMENTAL = Boolean.getBoolean("portecle.experimental");

    /** Default keystore table width - dictates width of this frame */
    private static final int DEFAULT_TABLE_WIDTH = 600;

    /** Default keystore table width - dictates height of this frame */
    private static final int DEFAULT_TABLE_HEIGHT = 400;

    /** Number of recent files to hold in the file menu */
    private static final int RECENT_FILES_LENGTH = 4;

    /** Menu index in the file menu for recent files to be inserted at */
    // EXPERIMENTAL enables/disables the PKCS #11 menu item
    private static final int RECENT_FILES_INDEX = EXPERIMENTAL ? 6 : 5;

    /** Default look & feel class name */
    private static final String DEFAULT_LOOK_FEEL = UIManager.getCrossPlatformLookAndFeelClassName();

    /** Our light metal theme */
    private static final LightMetalTheme METAL_THEME = new LightMetalTheme();

    /** Dummy password to use for PKCS #12 keystore entries
     * (passwords are not applicable for these). */
    private static final char[] PKCS12_DUMMY_PASSWORD = "password".toCharArray();

    /** Default CA certs keystore file */
    private static final String DEFAULT_CA_CERTS_FILE = new File(
        System.getProperty("java.home"), "lib" + File.separator + "security"
            + File.separator + FileChooserFactory.CACERTS_FILENAME).toString();

    /** The last directory accessed by the application */
    private LastDir m_lastDir = new LastDir();

    /** Use CA certs keystore file? */
    private boolean m_bUseCaCerts;

    /** CA certs keystore file */
    private File m_fCaCertsFile;

    /** CA certs keystore */
    private KeyStore m_caCertsKeyStore;

    /** KeystoreWrapper object containing the current keystore */
    private KeyStoreWrapper m_keyStoreWrap;

    /** The PRNG, cached for performance reasons */
    private SecureRandom m_rnd;

    /** Frame for Help System */
    private FHelp m_fHelp;

    /** Look & Feel setting made in options (picked up by saveAppPrefs) */
    private UIManager.LookAndFeelInfo m_lookFeelOptions;

    /** Look & Feel setting made in options (picked up by saveAppPrefs) */
    private Boolean m_bLookFeelDecorationOptions;

    ////////////////////////////////////////////////////////////
    // Menu bar controls
    ////////////////////////////////////////////////////////////

    /** File menu */
    private JMenuRecentFiles m_jmrfFile;

    /** Save keystore As menu item of File menu */
    private JMenuItem m_jmiSaveKeyStoreAs;

    /** Change keystore Type menu Tools menu */
    private JMenu m_jmChangeKeyStoreType;

    /** JKS menu item in Change Keystore Type menu */
    private JMenuItem m_jmiChangeKeyStoreTypeJks;

    /** Case sensitive JKS menu item in Change Keystore Type menu */
    private JMenuItem m_jmiChangeKeyStoreTypeCaseExactJks;

    /** JCEKS menu item in Change Keystore Type menu */
    private JMenuItem m_jmiChangeKeyStoreTypeJceks;

    /** PKCS #12 menu item in Change Keystore Type menu */
    private JMenuItem m_jmiChangeKeyStoreTypePkcs12;

    /** BKS menu item in Change Keystore Type menu */
    private JMenuItem m_jmiChangeKeyStoreTypeBks;

    /** UBER menu item in Change Keystore Type menu */
    private JMenuItem m_jmiChangeKeyStoreTypeUber;

    /** GKR menu item in Change Keystore Type menu */
    private JMenuItem m_jmiChangeKeyStoreTypeGkr;

    ////////////////////////////////////////////////////////////
    // Pop-up menu controls
    ////////////////////////////////////////////////////////////

    /** Key entry pop-up menu */
    private JPopupMenu m_jpmKey;

    /** Key pair entry pop-up menu */
    private JPopupMenu m_jpmKeyPair;

    /** Set Password menu item of key pair entry pop-up menu */
    private JMenuItem m_jmiSetKeyPairPass;

    /** Trusted Certificate entry pop-up menu */
    private JPopupMenu m_jpmCert;

    ////////////////////////////////////////////////////////////
    // Keystore table controls
    ////////////////////////////////////////////////////////////

    /** Panel to hold keystore entries table */
    private JPanel m_jpKeyStoreTable;

    /** Keystore entries table */
    private JTable m_jtKeyStore;

    ////////////////////////////////////////////////////////////
    // Status bar controls
    ////////////////////////////////////////////////////////////

    /** Label to display current application status messages */
    private JLabel m_jlStatusBar;

    ////////////////////////////////////////////////////////////
    // Actions - these are shared between the menu and toolbar
    ////////////////////////////////////////////////////////////

    /** New Keystore action */
    private final NewKeyStoreAction m_newKeyStoreAction = new NewKeyStoreAction();

    /** Open Keystore File action */
    private final OpenKeyStoreFileAction m_openKeyStoreFileAction = new OpenKeyStoreFileAction();

    /** Save Keystore action */
    private final SaveKeyStoreAction m_saveKeyStoreAction = new SaveKeyStoreAction();

    /** Examine Certificate action */
    private final ExamineCertAction m_examineCertAction = new ExamineCertAction();

    /** Examine SSL/TLS Connection action */
    private final ExamineCertSSLAction m_examineCertSSLAction = new ExamineCertSSLAction();

    /** Examine CSR action */
    private final ExamineCsrAction m_examineCsrAction = new ExamineCsrAction();

    /** Examine CRL action */
    private final ExamineCrlAction m_examineCrlAction = new ExamineCrlAction();

    /** Generate Key Pair action */
    private final GenKeyPairAction m_genKeyPairAction = new GenKeyPairAction();

    /** Import Trusted Certificate action */
    private final ImportTrustCertAction m_importTrustCertAction = new ImportTrustCertAction();

    /** Import Key Pair action */
    private final ImportKeyPairAction m_importKeyPairAction = new ImportKeyPairAction();

    /** Set Keystore Password action */
    private final SetKeyStorePassAction m_setKeyStorePassAction = new SetKeyStorePassAction();

    /** Keystore Report action */
    private final KeyStoreReportAction m_keyStoreReportAction = new KeyStoreReportAction();

    /** Help action */
    private final HelpAction m_helpAction = new HelpAction();

    /**
     * Creates a new FPortecle frame.
     */
    public FPortecle()
    {
        // Get and store non-GUI related application properties
        m_bUseCaCerts = m_appPrefs.getBoolean(
            m_res.getString("AppPrefs.UseCaCerts"), false);
        m_fCaCertsFile = new File(m_appPrefs.get(
            m_res.getString("AppPrefs.CaCertsFile"), DEFAULT_CA_CERTS_FILE));

        // Initialise GUI components
        initComponents();
    }

    /**
     * Initialise FPortecle frame's GUI components.
     */
    private void initComponents()
    {
        initStatusBar();
        initMenu();
        initToolBar();
        initPopupMenus();
        initTable();

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

        // Set application position according to application preferences
        // unless the relevant preferences are not present or are invalid
        int iXPos = m_appPrefs.getInt(m_res.getString("AppPrefs.XPos"), 0);
        int iYPos = m_appPrefs.getInt(m_res.getString("AppPrefs.YPos"), 0);

        if (iXPos <= 0 || iYPos <= 0) {
            // Centre the frame in the centre of the desktop
            setLocationRelativeTo(null);
        }
        else {
            // Use application property values for positioning
            setLocation(new Point(iXPos, iYPos));
        }

        // If frame is not completely visible then set it to default size
        // and center it
        if (!SwingUtilities.isRectangleContainingRectangle(new Rectangle(
            Toolkit.getDefaultToolkit().getScreenSize()), getBounds()))
        {
            m_jpKeyStoreTable.setPreferredSize(new Dimension(
                DEFAULT_TABLE_WIDTH, DEFAULT_TABLE_HEIGHT));
            setLocationRelativeTo(null);
        }

        // Set its icon
        setIconImage(getResImage("FPortecle.Icon.image"));
    }

    /**
     * Initialise FPortecle frame's main menu GUI components.
     */
    private void initMenu()
    {
        // The menu items that carry out the same function as toolbar buttons
        // use actions

        // The menu bar
        JMenuBar jmbMenuBar = new JMenuBar();

        // File menu
        m_jmrfFile = new JMenuRecentFiles(
            m_res.getString("FPortecle.m_jmrfFile.text"), RECENT_FILES_LENGTH,
            RECENT_FILES_INDEX);
        m_jmrfFile.setMnemonic(m_res.getString("FPortecle.m_jmrfFile.mnemonic").charAt(
            0));

        JMenuItem jmiNewKeyStore = new JMenuItem(m_newKeyStoreAction);
        jmiNewKeyStore.setToolTipText(null);
        new StatusBarChangeHandler(jmiNewKeyStore,
            (String) m_newKeyStoreAction.getValue(Action.LONG_DESCRIPTION),
            this);
        m_jmrfFile.add(jmiNewKeyStore);

        JMenuItem jmiOpenKeyStoreFile = new JMenuItem(m_openKeyStoreFileAction);
        jmiOpenKeyStoreFile.setToolTipText(null);
        new StatusBarChangeHandler(
            jmiOpenKeyStoreFile,
            (String) m_openKeyStoreFileAction.getValue(Action.LONG_DESCRIPTION),
            this);
        m_jmrfFile.add(jmiOpenKeyStoreFile);

        if (EXPERIMENTAL) {
            JMenuItem jmiOpenKeyStorePkcs11 = new JMenuItem(
                m_res.getString("FPortecle.jmiOpenKeyStorePkcs11.text"),
                m_res.getString("FPortecle.jmiOpenKeyStorePkcs11.mnemonic").charAt(
                    0));
            jmiOpenKeyStorePkcs11.setIcon(new ImageIcon(
                getResImage("FPortecle.jmiOpenKeyStorePkcs11.image")));
            jmiOpenKeyStorePkcs11.setToolTipText(null);
            if (ProviderUtil.getPkcs11Providers().isEmpty()) {
                jmiOpenKeyStorePkcs11.setEnabled(false);
            }
            m_jmrfFile.add(jmiOpenKeyStorePkcs11);
            jmiOpenKeyStorePkcs11.addActionListener(new ActionListener()
            {
                protected void act()
                {
                    openKeyStorePkcs11();
                }
            });
            new StatusBarChangeHandler(jmiOpenKeyStorePkcs11,
                m_res.getString("FPortecle.jmiOpenKeyStorePkcs11.statusbar"),
                this);
        }

        m_jmrfFile.addSeparator();

        JMenuItem jmiSaveKeyStore = new JMenuItem(m_saveKeyStoreAction);
        jmiSaveKeyStore.setToolTipText(null);
        new StatusBarChangeHandler(jmiSaveKeyStore,
            (String) m_saveKeyStoreAction.getValue(Action.LONG_DESCRIPTION),
            this);
        m_jmrfFile.add(jmiSaveKeyStore);

        m_jmiSaveKeyStoreAs = new JMenuItem(
            m_res.getString("FPortecle.m_jmiSaveKeyStoreAs.text"),
            m_res.getString("FPortecle.m_jmiSaveKeyStoreAs.mnemonic").charAt(0));
        m_jmiSaveKeyStoreAs.setIcon(new ImageIcon(
            getResImage("FPortecle.m_jmiSaveKeyStoreAs.image")));
        m_jmiSaveKeyStoreAs.setEnabled(false);
        m_jmrfFile.add(m_jmiSaveKeyStoreAs);
        m_jmiSaveKeyStoreAs.addActionListener(new ActionListener()
        {
            protected void act()
            {
                saveKeyStoreAs();
            }
        });
        new StatusBarChangeHandler(m_jmiSaveKeyStoreAs,
            m_res.getString("FPortecle.m_jmiSaveKeyStoreAs.statusbar"), this);

        m_jmrfFile.addSeparator();

        // Add recent files to file menu
        for (int iCnt = RECENT_FILES_LENGTH; iCnt > 0; iCnt--) {
            String sRecentFile = m_appPrefs.get(
                m_res.getString("AppPrefs.RecentFile") + iCnt, null);

            if (sRecentFile != null) {
                m_jmrfFile.add(createRecentFileMenuItem(new File(sRecentFile)));
            }
        }

        JMenuItem jmiExit = new JMenuItem(
            m_res.getString("FPortecle.jmiExit.text"), m_res.getString(
                "FPortecle.jmiExit.mnemonic").charAt(0));
        jmiExit.setIcon(new ImageIcon(getResImage("FPortecle.jmiExit.image")));
        m_jmrfFile.add(jmiExit);
        jmiExit.addActionListener(new ActionListener()
        {
            protected void act()
            {
                exitApplication();
            }
        });
        new StatusBarChangeHandler(jmiExit,
            m_res.getString("FPortecle.jmiExit.statusbar"), this);

        // Tools menu
        JMenu jmTools = new JMenu(m_res.getString("FPortecle.jmTools.text"));
        jmTools.setMnemonic(m_res.getString("FPortecle.jmTools.mnemonic").charAt(
            0));

        JMenuItem jmiGenKeyPair = new JMenuItem(m_genKeyPairAction);
        jmiGenKeyPair.setToolTipText(null);
        new StatusBarChangeHandler(jmiGenKeyPair,
            (String) m_genKeyPairAction.getValue(Action.LONG_DESCRIPTION),
            this);
        jmTools.add(jmiGenKeyPair);

        JMenuItem jmiImportTrustCert = new JMenuItem(m_importTrustCertAction);
        jmiImportTrustCert.setToolTipText(null);
        new StatusBarChangeHandler(
            jmiImportTrustCert,
            (String) m_importTrustCertAction.getValue(Action.LONG_DESCRIPTION),
            this);
        jmTools.add(jmiImportTrustCert);

        JMenuItem jmiImportKeyPair = new JMenuItem(m_importKeyPairAction);
        jmiImportKeyPair.setToolTipText(null);
        new StatusBarChangeHandler(jmiImportKeyPair,
            (String) m_importKeyPairAction.getValue(Action.LONG_DESCRIPTION),
            this);
        jmTools.add(jmiImportKeyPair);

        jmTools.addSeparator();

        JMenuItem jmiSetKeyStorePass = new JMenuItem(m_setKeyStorePassAction);
        jmiSetKeyStorePass.setToolTipText(null);
        new StatusBarChangeHandler(
            jmiSetKeyStorePass,
            (String) m_setKeyStorePassAction.getValue(Action.LONG_DESCRIPTION),
            this);
        jmTools.add(jmiSetKeyStorePass);

        m_jmChangeKeyStoreType = new JMenu(
            m_res.getString("FPortecle.m_jmChangeKeyStoreType.text"));
        m_jmChangeKeyStoreType.setIcon(new ImageIcon(
            getResImage("FPortecle.m_jmChangeKeyStoreType.image")));
        m_jmChangeKeyStoreType.setMnemonic(m_res.getString(
            "FPortecle.m_jmChangeKeyStoreType.mnemonic").charAt(0));
        m_jmChangeKeyStoreType.setEnabled(false);
        jmTools.add(m_jmChangeKeyStoreType);

        // Add Change Keystore Type sub-menu of Tools

        m_jmiChangeKeyStoreTypeJks = new JMenuItem(
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeJks.text"),
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeJks.mnemonic").charAt(
                0));
        m_jmiChangeKeyStoreTypeJks.setEnabled(false);
        m_jmiChangeKeyStoreTypeJks.addActionListener(new ActionListener()
        {
            protected void act()
            {
                changeKeyStoreType(KeyStoreType.JKS);
            }
        });
        new StatusBarChangeHandler(m_jmiChangeKeyStoreTypeJks,
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeJks.statusbar"),
            this);

        m_jmiChangeKeyStoreTypeCaseExactJks = new JMenuItem(
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeCaseExactJks.text"),
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeCaseExactJks.mnemonic").charAt(
                0));
        m_jmiChangeKeyStoreTypeCaseExactJks.setEnabled(false);
        m_jmiChangeKeyStoreTypeCaseExactJks.addActionListener(new ActionListener()
        {
            protected void act()
            {
                changeKeyStoreType(KeyStoreType.CaseExactJKS);
            }
        });
        new StatusBarChangeHandler(m_jmiChangeKeyStoreTypeCaseExactJks,
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeCaseExactJks.statusbar"),
            this);

        m_jmiChangeKeyStoreTypeJceks = new JMenuItem(
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeJceks.text"),
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeJceks.mnemonic").charAt(
                0));
        m_jmiChangeKeyStoreTypeJceks.setEnabled(false);
        m_jmiChangeKeyStoreTypeJceks.addActionListener(new ActionListener()
        {
            protected void act()
            {
                changeKeyStoreType(KeyStoreType.JCEKS);
            }
        });
        new StatusBarChangeHandler(
            m_jmiChangeKeyStoreTypeJceks,
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeJceks.statusbar"),
            this);

        m_jmiChangeKeyStoreTypePkcs12 = new JMenuItem(
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypePkcs12.text"),
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypePkcs12.mnemonic").charAt(
                0));
        m_jmiChangeKeyStoreTypePkcs12.setEnabled(false);
        m_jmiChangeKeyStoreTypePkcs12.addActionListener(new ActionListener()
        {
            protected void act()
            {
                changeKeyStoreType(KeyStoreType.PKCS12);
            }
        });
        new StatusBarChangeHandler(
            m_jmiChangeKeyStoreTypePkcs12,
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypePkcs12.statusbar"),
            this);

        m_jmiChangeKeyStoreTypeBks = new JMenuItem(
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeBks.text"),
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeBks.mnemonic").charAt(
                0));
        m_jmiChangeKeyStoreTypeBks.setEnabled(false);
        m_jmiChangeKeyStoreTypeBks.addActionListener(new ActionListener()
        {
            protected void act()
            {
                changeKeyStoreType(KeyStoreType.BKS);
            }
        });
        new StatusBarChangeHandler(m_jmiChangeKeyStoreTypeBks,
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeBks.statusbar"),
            this);

        m_jmiChangeKeyStoreTypeUber = new JMenuItem(
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeUber.text"),
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeUber.mnemonic").charAt(
                0));
        m_jmiChangeKeyStoreTypeUber.setEnabled(false);
        m_jmiChangeKeyStoreTypeUber.addActionListener(new ActionListener()
        {
            protected void act()
            {
                changeKeyStoreType(KeyStoreType.UBER);
            }
        });
        new StatusBarChangeHandler(
            m_jmiChangeKeyStoreTypeUber,
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeUber.statusbar"),
            this);

        m_jmiChangeKeyStoreTypeGkr = new JMenuItem(
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeGkr.text"),
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeGkr.mnemonic").charAt(
                0));
        m_jmiChangeKeyStoreTypeGkr.setEnabled(false);
        m_jmiChangeKeyStoreTypeGkr.addActionListener(new ActionListener()
        {
            protected void act()
            {
                changeKeyStoreType(KeyStoreType.GKR);
            }
        });
        new StatusBarChangeHandler(
            m_jmiChangeKeyStoreTypeGkr,
            m_res.getString("FPortecle.m_jmiChangeKeyStoreTypeGkr.statusbar"),
            this);

        m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeJks);
        m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypePkcs12);
        m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeJceks);
        m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeCaseExactJks);
        m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeBks);
        m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeUber);
        m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeGkr);

        // Others
        
        JMenuItem jmiKeyStoreReport = new JMenuItem(m_keyStoreReportAction);
        jmiKeyStoreReport.setToolTipText(null);
        new StatusBarChangeHandler(jmiKeyStoreReport,
            (String) m_keyStoreReportAction.getValue(Action.LONG_DESCRIPTION),
            this);
        jmTools.add(jmiKeyStoreReport);

        jmTools.addSeparator();

        JMenuItem jmiOptions = new JMenuItem(
            m_res.getString("FPortecle.jmiOptions.text"), m_res.getString(
                "FPortecle.jmiOptions.mnemonic").charAt(0));
        jmiOptions.setIcon(new ImageIcon(
            getResImage("FPortecle.jmiOptions.image")));
        jmTools.add(jmiOptions);
        jmiOptions.addActionListener(new ActionListener()
        {
            protected void act()
            {
                showOptions();
            }
        });
        new StatusBarChangeHandler(jmiOptions,
            m_res.getString("FPortecle.jmiOptions.statusbar"), this);

        // Examine menu
        JMenu jmExamine = new JMenu(
            m_res.getString("FPortecle.jmExamine.text"));
        jmExamine.setMnemonic(m_res.getString("FPortecle.jmExamine.mnemonic").charAt(
            0));

        JMenuItem jmiExamineCert = new JMenuItem(m_examineCertAction);
        jmiExamineCert.setToolTipText(null);
        new StatusBarChangeHandler(jmiExamineCert,
            (String) m_examineCertAction.getValue(Action.LONG_DESCRIPTION),
            this);
        jmExamine.add(jmiExamineCert);

        JMenuItem jmiExamineCertSSL = new JMenuItem(m_examineCertSSLAction);
        jmiExamineCertSSL.setToolTipText(null);
        new StatusBarChangeHandler(jmiExamineCertSSL,
            (String) m_examineCertSSLAction.getValue(Action.LONG_DESCRIPTION),
            this);
        jmExamine.add(jmiExamineCertSSL);

        JMenuItem jmiExamineCsr = new JMenuItem(m_examineCsrAction);
        jmiExamineCsr.setToolTipText(null);
        new StatusBarChangeHandler(jmiExamineCsr,
            (String) m_examineCsrAction.getValue(Action.LONG_DESCRIPTION),
            this);
        jmExamine.add(jmiExamineCsr);

        JMenuItem jmiExamineCrl = new JMenuItem(m_examineCrlAction);
        jmiExamineCrl.setToolTipText(null);
        new StatusBarChangeHandler(jmiExamineCrl,
            (String) m_examineCrlAction.getValue(Action.LONG_DESCRIPTION),
            this);
        jmExamine.add(jmiExamineCrl);

        // Help menu
        JMenu jmHelp = new JMenu(m_res.getString("FPortecle.jmHelp.text"));
        jmHelp.setMnemonic(m_res.getString("FPortecle.jmHelp.mnemonic").charAt(
            0));

        JMenuItem jmiHelp = new JMenuItem(m_helpAction);
        jmiHelp.setToolTipText(null);
        new StatusBarChangeHandler(jmiHelp,
            (String) m_helpAction.getValue(Action.LONG_DESCRIPTION), this);
        jmHelp.add(jmiHelp);

        // Online Resources menu (sub-menu of Help)
        JMenu jmOnlineResources = new JMenu(
            m_res.getString("FPortecle.jmOnlineResources.text"));
        jmOnlineResources.setIcon(new ImageIcon(
            getResImage("FPortecle.jmOnlineResources.image")));
        jmOnlineResources.setMnemonic(m_res.getString(
            "FPortecle.jmOnlineResources.mnemonic").charAt(0));
        jmHelp.add(jmOnlineResources);

        JMenuItem jmiWebsite = new JMenuItem(
            m_res.getString("FPortecle.jmiWebsite.text"), m_res.getString(
                "FPortecle.jmiWebsite.mnemonic").charAt(0));
        jmiWebsite.setIcon(new ImageIcon(
            getResImage("FPortecle.jmiWebsite.image")));
        jmOnlineResources.add(jmiWebsite);
        jmiWebsite.addActionListener(new ActionListener()
        {
            protected void act()
            {
                visitWebsite();
            }
        });
        new StatusBarChangeHandler(jmiWebsite,
            m_res.getString("FPortecle.jmiWebsite.statusbar"), this);

        JMenuItem jmiSFNetProject = new JMenuItem(
            m_res.getString("FPortecle.jmiSFNetProject.text"),
            m_res.getString("FPortecle.jmiSFNetProject.mnemonic").charAt(0));
        jmiSFNetProject.setIcon(new ImageIcon(
            getResImage("FPortecle.jmiSFNetProject.image")));
        jmOnlineResources.add(jmiSFNetProject);
        jmiSFNetProject.addActionListener(new ActionListener()
        {
            protected void act()
            {
                visitSFNetProject();
            }
        });
        new StatusBarChangeHandler(jmiSFNetProject,
            m_res.getString("FPortecle.jmiSFNetProject.statusbar"), this);

        JMenuItem jmiEmail = new JMenuItem(
            m_res.getString("FPortecle.jmiEmail.text"), m_res.getString(
                "FPortecle.jmiEmail.mnemonic").charAt(0));
        jmiEmail.setIcon(new ImageIcon(getResImage("FPortecle.jmiEmail.image")));
        jmOnlineResources.add(jmiEmail);
        jmiEmail.addActionListener(new ActionListener()
        {
            protected void act()
            {
                composeEmail();
            }
        });
        new StatusBarChangeHandler(jmiEmail,
            m_res.getString("FPortecle.jmiEmail.statusbar"), this);

        JMenuItem jmiMailList = new JMenuItem(
            m_res.getString("FPortecle.jmiMailList.text"), m_res.getString(
                "FPortecle.jmiMailList.mnemonic").charAt(0));
        jmiMailList.setIcon(new ImageIcon(
            getResImage("FPortecle.jmiMailList.image")));
        jmOnlineResources.add(jmiMailList);
        jmiMailList.addActionListener(new ActionListener()
        {
            protected void act()
            {
                visitMailListSignup();
            }
        });
        new StatusBarChangeHandler(jmiMailList,
            m_res.getString("FPortecle.jmiMailList.statusbar"), this);

        /* Update check disabled for now...
         JMenuItem jmiCheckUpdate = new JMenuItem(
         m_res.getString("FPortecle.jmiCheckUpdate.text"),
         m_res.getString("FPortecle.jmiCheckUpdate.mnemonic").charAt(0));
         jmiCheckUpdate.setIcon(
         new ImageIcon(getResImage("FPortecle.jmiCheckUpdate.image")));
         jmOnlineResources.add(jmiCheckUpdate);
         jmiCheckUpdate.addActionListener(new ActionListener() {
         protected void act() { checkForUpdate(); }});
         new StatusBarChangeHandler(
         jmiCheckUpdate,
         m_res.getString("FPortecle.jmiCheckUpdate.statusbar"),
         this);
         */

        JMenuItem jmiDonate = new JMenuItem(
            m_res.getString("FPortecle.jmiDonate.text"), m_res.getString(
                "FPortecle.jmiDonate.mnemonic").charAt(0));
        jmiDonate.setIcon(new ImageIcon(
            getResImage("FPortecle.jmiDonate.image")));
        jmiDonate.setToolTipText(null);
        jmHelp.add(jmiDonate);
        jmiDonate.addActionListener(new ActionListener()
        {
            protected void act()
            {
                makeDonation();
            }
        });
        new StatusBarChangeHandler(jmiDonate,
            m_res.getString("FPortecle.jmiDonate.statusbar"), this);

        jmHelp.addSeparator();

        JMenuItem jmiSecurityProviders = new JMenuItem(
            m_res.getString("FPortecle.jmiSecurityProviders.text"),
            m_res.getString("FPortecle.jmiSecurityProviders.mnemonic").charAt(
                0));
        jmiSecurityProviders.setIcon(new ImageIcon(
            getResImage("FPortecle.jmiSecurityProviders.image")));
        jmHelp.add(jmiSecurityProviders);
        jmiSecurityProviders.addActionListener(new ActionListener()
        {
            protected void act()
            {
                showSecurityProviders();
            }
        });
        new StatusBarChangeHandler(jmiSecurityProviders,
            m_res.getString("FPortecle.jmiSecurityProviders.statusbar"), this);

        JMenuItem jmiJars = new JMenuItem(
            m_res.getString("FPortecle.jmiJars.text"), m_res.getString(
                "FPortecle.jmiJars.mnemonic").charAt(0));
        jmiJars.setIcon(new ImageIcon(getResImage("FPortecle.jmiJars.image")));
        jmHelp.add(jmiJars);
        jmiJars.addActionListener(new ActionListener()
        {
            protected void act()
            {
                showJarInfo();
            }
        });
        new StatusBarChangeHandler(jmiJars,
            m_res.getString("FPortecle.jmiJars.statusbar"), this);

        jmHelp.addSeparator();

        JMenuItem jmiAbout = new JMenuItem(
            m_res.getString("FPortecle.jmiAbout.text"), m_res.getString(
                "FPortecle.jmiAbout.mnemonic").charAt(0));
        jmiAbout.setIcon(new ImageIcon(getResImage("FPortecle.jmiAbout.image")));
        jmHelp.add(jmiAbout);
        jmiAbout.addActionListener(new ActionListener()
        {
            protected void act()
            {
                showAbout();
            }
        });
        new StatusBarChangeHandler(jmiAbout,
            m_res.getString("FPortecle.jmiAbout.statusbar"), this);

        // Add the menus to the menu bar
        jmbMenuBar.add(m_jmrfFile);
        jmbMenuBar.add(jmTools);
        jmbMenuBar.add(jmExamine);
        jmbMenuBar.add(jmHelp);

        // Add menu bar to application frame
        setJMenuBar(jmbMenuBar);
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
        jmirfNew.setIcon(new ImageIcon(
            getResImage("FPortecle.OpenRecent.image")));
        jmirfNew.addActionListener(new RecentKeyStoreFileActionListener(
            fRecentFile, this));

        new StatusBarChangeHandler(jmirfNew, MessageFormat.format(
            m_res.getString("FPortecle.recentfile.statusbar"),
            new Object[] { fRecentFile }), this);
        return jmirfNew;
    }

    /**
     * Initialise FPortecle frame's toolbar GUI components.
     */
    private void initToolBar()
    {
        // Create the "new" toolbar button
        JButton jbNewKeyStore = new JButton();
        jbNewKeyStore.setAction(m_newKeyStoreAction);
        jbNewKeyStore.setText(null); // Don't share text from action
        // Get around bug with action mnemonics on toolbar buttons
        jbNewKeyStore.setMnemonic(0);
        jbNewKeyStore.setFocusable(false);
        jbNewKeyStore.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String) m_newKeyStoreAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "open" toolbar button
        JButton jbOpenKeyStoreFile = new JButton();
        jbOpenKeyStoreFile.setAction(m_openKeyStoreFileAction);
        jbOpenKeyStoreFile.setText(null); // Don't share text from action
        // Get around bug with action mnemonics on toolbar buttons
        jbOpenKeyStoreFile.setMnemonic(0);
        jbOpenKeyStoreFile.setFocusable(false);
        jbOpenKeyStoreFile.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String) m_openKeyStoreFileAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "save" toolbar button
        JButton jbSaveKeyStore = new JButton();
        jbSaveKeyStore.setAction(m_saveKeyStoreAction);
        jbSaveKeyStore.setText(null); // Don't share text from action
        // Get around bug with action mnemonics on toolbar buttons
        jbSaveKeyStore.setMnemonic(0);
        jbSaveKeyStore.setFocusable(false);
        jbSaveKeyStore.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String) m_saveKeyStoreAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "generate key pair" toolbar button
        JButton jbGenKeyPair = new JButton();
        jbGenKeyPair.setAction(m_genKeyPairAction);
        jbGenKeyPair.setText(null); // Don't share text from action
        // Get around bug with action mnemonics on toolbar buttons
        jbGenKeyPair.setMnemonic(0);
        jbGenKeyPair.setFocusable(false);
        jbGenKeyPair.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String) m_genKeyPairAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "import trusted certificate" toolbar button
        JButton jbImportTrustCert = new JButton();
        jbImportTrustCert.setAction(m_importTrustCertAction);
        jbImportTrustCert.setText(null); // Don't share text from action
        // Get around bug with action mnemonics on toolbar buttons
        jbImportTrustCert.setMnemonic(0);
        jbImportTrustCert.setFocusable(false);
        jbImportTrustCert.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String) m_importTrustCertAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "import key pair" toolbar button
        JButton jbImportKeyPair = new JButton();
        jbImportKeyPair.setAction(m_importKeyPairAction);
        jbImportKeyPair.setText(null); // Don't share text from action
        // Get around bug with action mnemonics on toolbar buttons
        jbImportKeyPair.setMnemonic(0);
        jbImportKeyPair.setFocusable(false);
        jbImportKeyPair.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String) m_importKeyPairAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "set keystore password" toolbar button
        JButton jbSetKeyStorePass = new JButton();
        jbSetKeyStorePass.setAction(m_setKeyStorePassAction);
        jbSetKeyStorePass.setText(null); // Don't share text from action
        // Get around bug with action mnemonics on toolbar buttons
        jbSetKeyStorePass.setMnemonic(0);
        jbSetKeyStorePass.setFocusable(false);
        jbSetKeyStorePass.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String) m_setKeyStorePassAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "keystore report" toolbar button
        JButton jbKeyStoreReport = new JButton();
        jbKeyStoreReport.setAction(m_keyStoreReportAction);
        jbKeyStoreReport.setText(null); // Don't share text from action
        // Get around bug with action mnemonics on toolbar buttons
        jbKeyStoreReport.setMnemonic(0);
        jbKeyStoreReport.setFocusable(false);
        jbKeyStoreReport.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String) m_keyStoreReportAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "examine certificate" toolbar button
        JButton jbExamineCert = new JButton();
        jbExamineCert.setAction(m_examineCertAction);
        jbExamineCert.setText(null); // Don't share text from action
        // Get around bug with action mnemonics on toolbar buttons
        jbExamineCert.setMnemonic(0);
        jbExamineCert.setFocusable(false);
        jbExamineCert.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String) m_examineCertAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "examine crl" toolbar button
        JButton jbExamineCrl = new JButton();
        jbExamineCrl.setAction(m_examineCrlAction);
        jbExamineCrl.setText(null); // Don't share text from action
        // Get around bug with action mnemonics on toolbar buttons
        jbExamineCrl.setMnemonic(0);
        jbExamineCrl.setFocusable(false);
        jbExamineCrl.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String) m_examineCrlAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // Create the "help" toolbar button
        JButton jbHelp = new JButton();
        jbHelp.setAction(m_helpAction);
        jbHelp.setText(null); // Don't share text from action
        // Get around bug with action mnemonics on toolbar buttons
        jbHelp.setMnemonic(0);
        jbHelp.setFocusable(false);
        jbHelp.addMouseListener(new MouseAdapter()
        {
            public void mouseEntered(MouseEvent evt)
            {
                setStatusBarText((String) m_helpAction.getValue(Action.LONG_DESCRIPTION));
            }

            public void mouseExited(MouseEvent evt)
            {
                setDefaultStatusBarText();
            }
        });

        // The toolbar
        JToolBar jtbToolBar = new JToolBar();
        jtbToolBar.setFloatable(false);
        jtbToolBar.setRollover(true);
        jtbToolBar.setName(m_res.getString("FPortecle.jtbToolBar.name"));

        // Add the buttons to the toolbar - use visible separators for all L&Fs
        jtbToolBar.add(jbNewKeyStore);
        jtbToolBar.add(jbOpenKeyStoreFile);
        jtbToolBar.add(jbSaveKeyStore);

        JSeparator separator1 = new JSeparator(SwingConstants.VERTICAL);
        separator1.setMaximumSize(new Dimension(3, 16));
        jtbToolBar.add(separator1);

        jtbToolBar.add(jbGenKeyPair);
        jtbToolBar.add(jbImportTrustCert);
        jtbToolBar.add(jbImportKeyPair);
        jtbToolBar.add(jbSetKeyStorePass);
        jtbToolBar.add(jbKeyStoreReport);

        JSeparator separator2 = new JSeparator(SwingConstants.VERTICAL);
        separator2.setMaximumSize(new Dimension(3, 16));
        jtbToolBar.add(separator2);

        jtbToolBar.add(jbExamineCert);
        jtbToolBar.add(jbExamineCrl);

        JSeparator separator3 = new JSeparator(SwingConstants.VERTICAL);
        separator3.setMaximumSize(new Dimension(3, 16));
        jtbToolBar.add(separator3);

        jtbToolBar.add(jbHelp);

        // Add the toolbar to the frame
        getContentPane().add(jtbToolBar, BorderLayout.NORTH);
    }

    /**
     * Initialise FPortecle frame's keystore content table GUI components.
     */
    private void initTable()
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
        // Top accomodates entry icons with spare space (16 pixels tall)
        m_jtKeyStore.setRowHeight(18);

        // Add custom renderers for the table headers and cells
        for (int iCnt = 0; iCnt < m_jtKeyStore.getColumnCount(); iCnt++) {
            TableColumn column = m_jtKeyStore.getColumnModel().getColumn(iCnt);
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

        // Set alias columns width according to the relevant application
        // property unless the property is not present or is invalid.
        int iAliasWidth = m_appPrefs.getInt(
            m_res.getString("AppPrefs.AliasWidth"), 0);

        TableColumn aliasCol = m_jtKeyStore.getColumnModel().getColumn(1);
        aliasCol.setMinWidth(20);
        aliasCol.setMaxWidth(10000);

        if (iAliasWidth <= 0) {
            aliasCol.setPreferredWidth(350);
        }
        else {
            aliasCol.setPreferredWidth(iAliasWidth);
        }

        // Put the table into a scroll pane
        JScrollPane jspKeyStoreTable = new JScrollPane(m_jtKeyStore,
            JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
            JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        jspKeyStoreTable.getViewport().setBackground(
            m_jtKeyStore.getBackground());

        // Get the size of the keystore table panel from the application
        // preferences
        int iWidth = m_appPrefs.getInt(m_res.getString("AppPrefs.TableWidth"),
            0);
        int iHeight = m_appPrefs.getInt(
            m_res.getString("AppPrefs.TableHeight"), 0);

        // Put the scroll pane into a panel.  The preferred size of the panel
        // dictates the size of the entire frame
        m_jpKeyStoreTable = new JPanel(new BorderLayout(10, 10));

        if (iWidth <= 0 || iHeight <= 0) {
            m_jpKeyStoreTable.setPreferredSize(new Dimension(
                DEFAULT_TABLE_WIDTH, DEFAULT_TABLE_HEIGHT));
        }
        else {
            m_jpKeyStoreTable.setPreferredSize(new Dimension(iWidth, iHeight));
        }

        m_jpKeyStoreTable.add(jspKeyStoreTable, BorderLayout.CENTER);
        m_jpKeyStoreTable.setBorder(new EmptyBorder(3, 3, 3, 3));

        /* Add mouse listeners to show pop-up menus when table entries are
         clicked upon; maybeShowPopup for both mousePressed and mouseReleased
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
     * Initialise FPortecle frame's status bar GUI components.
     */
    private void initStatusBar()
    {
        m_jlStatusBar = new JLabel();

        m_jlStatusBar.setBorder(new CompoundBorder(
            new EmptyBorder(3, 3, 3, 3), new CompoundBorder(new BevelBorder(
                BevelBorder.LOWERED), new EmptyBorder(0, 2, 0, 2))));
        setDefaultStatusBarText();

        getContentPane().add(m_jlStatusBar, BorderLayout.SOUTH);
    }

    /**
     * Initialise FPortecle frame's popup menu GUI components.  These are
     * invoked when rows of specific types are clicked upon in the keystore
     * table.
     */
    private void initPopupMenus()
    {
        // Initialise key-only entry pop-up menu including mnemonics
        // and listeners
        m_jpmKey = new JPopupMenu();

        JMenuItem jmiKeyDelete = new JMenuItem(
            m_res.getString("FPortecle.jmiKeyDelete.text"),
            m_res.getString("FPortecle.jmiKeyDelete.mnemonic").charAt(0));
        jmiKeyDelete.setIcon(new ImageIcon(
            getResImage("FPortecle.jmiKeyDelete.image")));
        jmiKeyDelete.addActionListener(new ActionListener()
        {
            protected void act()
            {
                deleteSelectedEntry();
            }
        });
        new StatusBarChangeHandler(jmiKeyDelete,
            m_res.getString("FPortecle.jmiKeyDelete.statusbar"), this);

        m_jpmKey.add(jmiKeyDelete);

        // Initialise key pair entry pop-up menu including mnemonics
        // and listeners
        m_jpmKeyPair = new JPopupMenu();

        JMenuItem jmiKeyPairCertDetails = new JMenuItem(
            m_res.getString("FPortecle.jmiKeyPairCertDetails.text"),
            m_res.getString("FPortecle.jmiKeyPairCertDetails.mnemonic").charAt(
                0));
        jmiKeyPairCertDetails.setIcon(new ImageIcon(
            getResImage("FPortecle.jmiKeyPairCertDetails.image")));
        jmiKeyPairCertDetails.addActionListener(new ActionListener()
        {
            protected void act()
            {
                showSelectedEntry();
            }
        });
        new StatusBarChangeHandler(jmiKeyPairCertDetails,
            m_res.getString("FPortecle.jmiKeyPairCertDetails.statusbar"), this);

        JMenuItem jmiKeyPairExport = new JMenuItem(
            m_res.getString("FPortecle.jmiKeyPairExport.text"),
            m_res.getString("FPortecle.jmiKeyPairExport.mnemonic").charAt(0));
        jmiKeyPairExport.setIcon(new ImageIcon(
            getResImage("FPortecle.jmiKeyPairExport.image")));

        jmiKeyPairExport.addActionListener(new ActionListener()
        {
            protected void act()
            {
                exportSelectedEntry();
            }
        });
        new StatusBarChangeHandler(jmiKeyPairExport,
            m_res.getString("FPortecle.jmiKeyPairExport.statusbar"), this);

        JMenuItem jmiGenerateCSR = new JMenuItem(
            m_res.getString("FPortecle.jmiGenerateCSR.text"), m_res.getString(
                "FPortecle.jmiGenerateCSR.mnemonic").charAt(0));
        jmiGenerateCSR.setIcon(new ImageIcon(
            getResImage("FPortecle.jmiGenerateCSR.image")));
        jmiGenerateCSR.addActionListener(new ActionListener()
        {
            protected void act()
            {
                generateCsrSelectedEntry();
            }
        });
        new StatusBarChangeHandler(jmiGenerateCSR,
            m_res.getString("FPortecle.jmiGenerateCSR.statusbar"), this);

        JMenuItem jmiImportCAReply = new JMenuItem(
            m_res.getString("FPortecle.jmiImportCAReply.text"),
            m_res.getString("FPortecle.jmiImportCAReply.mnemonic").charAt(0));
        jmiImportCAReply.setIcon(new ImageIcon(
            getResImage("FPortecle.jmiImportCAReply.image")));
        jmiImportCAReply.addActionListener(new ActionListener()
        {
            protected void act()
            {
                importCAReplySelectedEntry();
            }
        });
        new StatusBarChangeHandler(jmiImportCAReply,
            m_res.getString("FPortecle.jmiImportCAReply.statusbar"), this);

        m_jmiSetKeyPairPass = new JMenuItem(
            m_res.getString("FPortecle.m_jmiSetKeyPairPass.text"),
            m_res.getString("FPortecle.m_jmiSetKeyPairPass.mnemonic").charAt(0));
        m_jmiSetKeyPairPass.setIcon(new ImageIcon(
            getResImage("FPortecle.m_jmiSetKeyPairPass.image")));
        m_jmiSetKeyPairPass.addActionListener(new ActionListener()
        {
            protected void act()
            {
                setPasswordSelectedEntry();
            }
        });
        new StatusBarChangeHandler(m_jmiSetKeyPairPass,
            m_res.getString("FPortecle.m_jmiSetKeyPairPass.statusbar"), this);

        JMenuItem jmiKeyPairDelete = new JMenuItem(
            m_res.getString("FPortecle.jmiKeyPairDelete.text"),
            m_res.getString("FPortecle.jmiKeyPairDelete.mnemonic").charAt(0));
        jmiKeyPairDelete.setIcon(new ImageIcon(
            getResImage("FPortecle.jmiKeyPairDelete.image")));
        jmiKeyPairDelete.addActionListener(new ActionListener()
        {
            protected void act()
            {
                deleteSelectedEntry();
            }
        });
        new StatusBarChangeHandler(jmiKeyPairDelete,
            m_res.getString("FPortecle.jmiKeyPairDelete.statusbar"), this);

        JMenuItem jmiKeyPairClone = new JMenuItem(
            m_res.getString("FPortecle.jmiKeyPairClone.text"), m_res.getString(
                "FPortecle.jmiKeyPairClone.mnemonic").charAt(0));
        jmiKeyPairClone.setIcon(new ImageIcon(getResImage("FPortecle.jmiKeyPairClone.image")));
        jmiKeyPairClone.addActionListener(new ActionListener()
        {
            protected void act()
            {
                cloneSelectedKeyEntry();
            }
        });
        new StatusBarChangeHandler(jmiKeyPairClone,
            m_res.getString("FPortecle.jmiKeyPairClone.statusbar"), this);

        JMenuItem jmiKeyPairRename = new JMenuItem(
            m_res.getString("FPortecle.jmiKeyPairRename.text"),
            m_res.getString("FPortecle.jmiKeyPairRename.mnemonic").charAt(0));
        jmiKeyPairRename.setIcon(new ImageIcon(
            getResImage("FPortecle.jmiKeyPairRename.image")));
        jmiKeyPairRename.addActionListener(new ActionListener()
        {
            protected void act()
            {
                renameSelectedEntry();
            }
        });
        new StatusBarChangeHandler(jmiKeyPairRename,
            m_res.getString("FPortecle.jmiKeyPairRename.statusbar"), this);

        m_jpmKeyPair.add(jmiKeyPairCertDetails);
        m_jpmKeyPair.addSeparator();
        m_jpmKeyPair.add(jmiKeyPairExport);
        m_jpmKeyPair.add(jmiGenerateCSR);
        m_jpmKeyPair.add(jmiImportCAReply);
        m_jpmKeyPair.addSeparator();
        m_jpmKeyPair.add(m_jmiSetKeyPairPass);
        m_jpmKeyPair.add(jmiKeyPairDelete);
        m_jpmKeyPair.add(jmiKeyPairClone);
        m_jpmKeyPair.add(jmiKeyPairRename);

        // Initialise Trusted Certificate entry pop-up menu including
        // mnemonics and listeners
        m_jpmCert = new JPopupMenu();

        JMenuItem jmiTrustCertDetails = new JMenuItem(
            m_res.getString("FPortecle.jmiTrustCertDetails.text"),
            m_res.getString("FPortecle.jmiTrustCertDetails.mnemonic").charAt(0));
        jmiTrustCertDetails.setIcon(new ImageIcon(
            getResImage("FPortecle.jmiTrustCertDetails.image")));
        jmiTrustCertDetails.addActionListener(new ActionListener()
        {
            protected void act()
            {
                showSelectedEntry();
            }
        });
        new StatusBarChangeHandler(jmiTrustCertDetails,
            m_res.getString("FPortecle.jmiTrustCertDetails.statusbar"), this);

        JMenuItem jmiTrustCertExport = new JMenuItem(
            m_res.getString("FPortecle.jmiTrustCertExport.text"),
            m_res.getString("FPortecle.jmiTrustCertExport.mnemonic").charAt(0));
        jmiTrustCertExport.setIcon(new ImageIcon(
            getResImage("FPortecle.jmiTrustCertExport.image")));
        jmiTrustCertExport.addActionListener(new ActionListener()
        {
            protected void act()
            {
                exportSelectedEntry();
            }
        });
        new StatusBarChangeHandler(jmiTrustCertExport,
            m_res.getString("FPortecle.jmiTrustCertExport.statusbar"), this);

        JMenuItem jmiTrustCertDelete = new JMenuItem(
            m_res.getString("FPortecle.jmiTrustCertDelete.text"),
            m_res.getString("FPortecle.jmiTrustCertDelete.mnemonic").charAt(0));
        jmiTrustCertDelete.setIcon(new ImageIcon(
            getResImage("FPortecle.jmiTrustCertDelete.image")));
        jmiTrustCertDelete.addActionListener(new ActionListener()
        {
            protected void act()
            {
                deleteSelectedEntry();
            }
        });
        new StatusBarChangeHandler(jmiTrustCertDelete,
            m_res.getString("FPortecle.jmiTrustCertDelete.statusbar"), this);

        JMenuItem jmiTrustCertClone = new JMenuItem(
            m_res.getString("FPortecle.jmiTrustCertClone.text"), m_res.getString(
                "FPortecle.jmiTrustCertClone.mnemonic").charAt(0));
        jmiTrustCertClone.setIcon(new ImageIcon(getResImage("FPortecle.jmiTrustCertClone.image")));
        jmiTrustCertClone.addActionListener(new ActionListener()
        {
            protected void act()
            {
                cloneSelectedCertificateEntry();
            }
        });
        new StatusBarChangeHandler(jmiTrustCertClone,
            m_res.getString("FPortecle.jmiTrustCertClone.statusbar"), this);

        JMenuItem jmiTrustCertRename = new JMenuItem(
            m_res.getString("FPortecle.jmiTrustCertRename.text"),
            m_res.getString("FPortecle.jmiTrustCertRename.mnemonic").charAt(0));
        jmiTrustCertRename.setIcon(new ImageIcon(
            getResImage("FPortecle.jmiTrustCertRename.image")));
        jmiTrustCertRename.addActionListener(new ActionListener()
        {
            protected void act()
            {
                renameSelectedEntry();
            }
        });
        new StatusBarChangeHandler(jmiTrustCertRename,
            m_res.getString("FPortecle.jmiTrustCertRename.statusbar"), this);

        m_jpmCert.add(jmiTrustCertDetails);
        m_jpmCert.addSeparator();
        m_jpmCert.add(jmiTrustCertExport);
        m_jpmCert.addSeparator();
        m_jpmCert.add(jmiTrustCertDelete);
        m_jpmCert.add(jmiTrustCertClone);
        m_jpmCert.add(jmiTrustCertRename);
    }

    /**
     * Show the appropriate pop-up menu if the originating mouse event
     * indicates that the user clicked upon a keystore entry in the UI
     * table and the entry is of type key pair or trusted certificate.
     *
     * @param evt The mouse event
     */
    private void maybeShowPopup(MouseEvent evt)
    {
        if (evt.isPopupTrigger()) {
            // What row and column were clicked upon (if any)?
            Point point = new Point(evt.getX(), evt.getY());
            int iRow = m_jtKeyStore.rowAtPoint(point);
            //int iCol = m_jtKeyStore.columnAtPoint(point);

            if (iRow != -1) {
                // Make the row that was clicked upon the selected one
                m_jtKeyStore.setRowSelectionInterval(iRow, iRow);

                // Show one menu if the keystore entry is of type key pair...
                Object currEntry = m_jtKeyStore.getValueAt(iRow, 0);
                if (currEntry.equals(KeyStoreTableModel.KEY_PAIR_ENTRY)) {
                    m_jpmKeyPair.show(evt.getComponent(), evt.getX(),
                        evt.getY());
                }
                // ...and another if the type is trusted certificate
                else if (currEntry.equals(KeyStoreTableModel.TRUST_CERT_ENTRY)) {
                    m_jpmCert.show(evt.getComponent(), evt.getX(), evt.getY());
                }
                // ...and yet another for key-only entries
                else if (currEntry.equals(KeyStoreTableModel.KEY_ENTRY)) {
                    m_jpmKey.show(evt.getComponent(), evt.getX(), evt.getY());
                }
                // What's this?
                else {
                    System.err.println("WARNING: popup context menu requested " +
                        "for unknown entry: " + currEntry);
                }
            }
        }
    }

    /**
     * Check if a double click occurred on the keystore table.  If it has
     * show the certificate details of the entry clicked upon.
     *
     * @param evt The mouse event
     */
    private void keyStoreTableDoubleClick(MouseEvent evt)
    {
        if (evt.getClickCount() > 1) {
            // What row and column were clicked upon (if any)?
            Point point = new Point(evt.getX(), evt.getY());
            int iRow = m_jtKeyStore.rowAtPoint(point);

            // Entry clicked upon
            if (iRow != -1) {
                // Get the entry type of the row
                //KeyStoreTableModel tableModel =
                //    (KeyStoreTableModel) m_jtKeyStore.getModel();

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
        DAbout dAbout = new DAbout(this, true);
        dAbout.setLocationRelativeTo(this);
        dAbout.setVisible(true);
    }

    /**
     * Generate a key pair (with certificate) in the currently opened keystore.
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

        if (!dGenerateKeyPair.isSuccessful()) {
            return false; // User cancelled the dialog
        }

        int iKeySize = dGenerateKeyPair.getKeySize();
        KeyPairType keyPairType = dGenerateKeyPair.getKeyPairType();

        // Display the Generating Key Pair dialog - generates the key pair
        DGeneratingKeyPair dGeneratingKeyPair = new DGeneratingKeyPair(this,
            true, keyPairType, iKeySize);
        dGeneratingKeyPair.setLocationRelativeTo(this);
        dGeneratingKeyPair.startKeyPairGeneration();
        dGeneratingKeyPair.setVisible(true);

        KeyPair keyPair = dGeneratingKeyPair.getKeyPair();

        if (keyPair == null) {
            return false; // User cancelled the dialog or error occured
        }

        /* Now display the certificate generation dialog supplying the
         key pair and signature algorithm - this will update the keystore
         with the key pair for us */
        DGenerateCertificate dGenerateCertificate = new DGenerateCertificate(
            this, m_res.getString("FPortecle.GenerateCertificate.Title"),
            true, keyPair, keyPairType);
        dGenerateCertificate.setLocationRelativeTo(this);
        dGenerateCertificate.setVisible(true);

        X509Certificate certificate = dGenerateCertificate.getCertificate();

        if (certificate == null) {
            return false; // user cancelled dialog or error occurred
        }

        // Get the keystore
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        // Get an alias for the new keystore entry
        String sAlias = null;

        // Get the alias
        DGetAlias dGetAlias = new DGetAlias(this,
            m_res.getString("DGenerateCertificate.KeyPairEntryAlias.Title"),
            true, X509CertUtil.getCertificateAlias(certificate).toLowerCase());
        dGetAlias.setLocationRelativeTo(this);
        dGetAlias.setVisible(true);
        sAlias = dGetAlias.getAlias();

        if (sAlias == null) {
            return false;
        }

        // Alias to possibly delete before adding new one
        String sAliasToDelete = null;
        
        try {
            // Check entry does not already exist in the keystore
            if (keyStore.containsAlias(sAlias)) {
                String sMessage = MessageFormat.format(
                    m_res.getString("DGenerateCertificate.OverwriteAlias.message"),
                    new String[] { sAlias });

                int iSelected = JOptionPane.showConfirmDialog(
                    this,
                    sMessage,
                    m_res.getString("DGenerateCertificate.KeyPairEntryAlias.Title"),
                    JOptionPane.YES_NO_OPTION);
                if (iSelected != JOptionPane.YES_OPTION) {
                    return false;
                }
                // Otherwise carry on - delete old entry later
                sAliasToDelete = sAlias;
            }
        }
        catch (KeyStoreException ex) {
            displayException(ex);
            return false;
        }

        // Get a password for the new keystore entry (only relevant if
        // the keystore is not PKCS #12)
        char[] cPassword = PKCS12_DUMMY_PASSWORD;

        if (!keyStore.getType().equals(KeyStoreType.PKCS12.toString())) {
            DGetNewPassword dGetNewPassword = new DGetNewPassword(
                this,
                m_res.getString("DGenerateCertificate.KeyPairEntryPassword.Title"),
                true);
            dGetNewPassword.setLocationRelativeTo(this);
            dGetNewPassword.setVisible(true);
            cPassword = dGetNewPassword.getPassword();

            if (cPassword == null) {
                return false;
            }
        }

        // Place the private key and certificate into the keystore and update
        // the keystore wrapper
        try {
            // If needed, delete old entry first
            if (sAliasToDelete != null) {
                keyStore.deleteEntry(sAliasToDelete);
            }
            // Store the new one
            keyStore.setKeyEntry(sAlias, keyPair.getPrivate(), cPassword,
                new X509Certificate[] { certificate });
            m_keyStoreWrap.setEntryPassword(sAlias, cPassword);
            m_keyStoreWrap.setChanged(true);
        }
        catch (KeyStoreException ex) {
            displayException(ex);
            return false;
        }

        // Update the frame's components and title
        updateControls();
        updateTitle();

        // Display success message
        JOptionPane.showMessageDialog(this,
            m_res.getString("FPortecle.KeyPairGenerationSuccessful.message"),
            m_res.getString("FPortecle.GenerateCertificate.Title"),
            JOptionPane.INFORMATION_MESSAGE);
        return true;
    }

    /**
     * Open a keystore file from disk.
     *
     * @return True if a keystore is opened, false otherwise
     */
    private boolean openKeyStoreFile()
    {
        // Does the current keystore contain unsaved changes?
        if (needSave()) {
            // Yes - ask the user if it should be saved
            int iWantSave = wantSave();

            if ((iWantSave == JOptionPane.YES_OPTION && !saveKeyStore())
                || iWantSave == JOptionPane.CANCEL_OPTION)
            {
                return false;
            }
        }

        // Let the user choose a file to open from
        JFileChooser chooser = FileChooserFactory.getKeyStoreFileChooser(null);

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FPortecle.OpenKeyStoreFile.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showOpenDialog(this);
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            File fOpenFile = chooser.getSelectedFile();

            // File chosen - open the keystore
            if (openKeyStoreFile(fOpenFile)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Open the supplied keystore file from disk.
     *
     * @param fKeyStore The keystore file
     * @return True if a keystore is opened, false otherwise
     */
    /* package private */boolean openKeyStoreFile(File fKeyStore)
    {
        // The keystore does not exist
        if (!fKeyStore.exists()) {
            JOptionPane.showMessageDialog(this, MessageFormat.format(
                m_res.getString("FPortecle.FileNotFound.message"),
                new Object[] { fKeyStore }),
                m_res.getString("FPortecle.OpenKeyStoreFile.Title"),
                JOptionPane.WARNING_MESSAGE);
            return false;
        }
        // The keystore file is not a file
        else if (!fKeyStore.isFile()) {
            JOptionPane.showMessageDialog(this, MessageFormat.format(
                m_res.getString("FPortecle.NotFile.message"),
                new Object[] { fKeyStore }),
                m_res.getString("FPortecle.OpenKeyStoreFile.Title"),
                JOptionPane.WARNING_MESSAGE);
            return false;
        }

        // Get the user to enter the keystore's password
        DGetPassword dGetPassword = new DGetPassword(this,
            MessageFormat.format(
                m_res.getString("FPortecle.GetKeyStorePassword.Title"),
                new String[] { fKeyStore.getName() }), true);
        dGetPassword.setLocationRelativeTo(this);
        dGetPassword.setVisible(true);
        char[] cPassword = dGetPassword.getPassword();

        if (cPassword == null) {
            return false;
        }

        try {
            // Load the keystore - try to open as each of the allowed
            // types in turn until successful
            KeyStore openedKeyStore = null;

            // Types
            KeyStoreType[] keyStoreTypes = KeyStoreUtil.getAvailableTypes();

            // Exceptions
            CryptoException[] cexs = new CryptoException[keyStoreTypes.length];

            // Tried types
            StringBuffer tried = new StringBuffer(); 
            
            for (int iCnt = 0; iCnt < keyStoreTypes.length; iCnt++) {
                tried.append(", ").append(keyStoreTypes[iCnt].toPrettyString());
                try {
                    openedKeyStore = KeyStoreUtil.loadKeyStore(fKeyStore,
                        cPassword, keyStoreTypes[iCnt]);
                    break; // Success
                }
                catch (CryptoException cex) {
                    cexs[iCnt] = cex;
                }
            }

            if (openedKeyStore == null) {
                // None of the types worked - show each of the errors?
                if (tried.length() > 2) {
                    tried.delete(0, 2); // Chop leading ", "
                }
                int iSelected = JOptionPane.showConfirmDialog(
                    this,
                    MessageFormat.format(
                        m_res.getString("FPortecle.NoOpenKeyStoreFile.message"),
                        new Object[] { fKeyStore, tried }),
                    m_res.getString("FPortecle.OpenKeyStoreFile.Title"),
                    JOptionPane.YES_NO_OPTION);
                if (iSelected == JOptionPane.YES_OPTION) {
                    for (int iCnt = 0; iCnt < cexs.length; iCnt++) {
                        displayException(cexs[iCnt]);
                    }
                }

                return false;
            }

            // Create a keystore wrapper for the keystore
            m_keyStoreWrap = new KeyStoreWrapper(openedKeyStore, fKeyStore,
                cPassword);

            // Update the frame's components and title
            updateControls();
            updateTitle();

            // Add keystore file to recent files in file menu
            m_jmrfFile.add(createRecentFileMenuItem(fKeyStore));

            // Update last accessed directory
            m_lastDir.updateLastDir(fKeyStore);

            return true;
        }
        catch (FileNotFoundException ex) {
            JOptionPane.showMessageDialog(this, MessageFormat.format(
                m_res.getString("FPortecle.NoReadFile.message"),
                new Object[] { fKeyStore }),
                m_res.getString("FPortecle.OpenKeyStoreFile.Title"),
                JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (Exception ex) {
            displayException(ex);
            return false;
        }
    }

    /**
     * Open a PKCS #11 keystore.
     *
     * @return True if a keystore is opened, false otherwise
     */
    private boolean openKeyStorePkcs11()
    {
        // Does the current keystore contain unsaved changes?
        if (needSave()) {
            // Yes - ask the user if it should be saved
            int iWantSave = wantSave();

            if ((iWantSave == JOptionPane.YES_OPTION && !saveKeyStore())
                || iWantSave == JOptionPane.CANCEL_OPTION)
            {
                return false;
            }
        }

        DChoosePkcs11Provider chooser = new DChoosePkcs11Provider(this,
            m_res.getString("FPortecle.ChoosePkcs11Provider.Title"), true,
            null);
        chooser.setLocationRelativeTo(this);
        chooser.setVisible(true);

        String provider = chooser.getProvider();
        return (provider == null) ? false : openKeyStorePkcs11(provider);
    }

    /**
     * Open the supplied PKCS #11 keystore.
     *
     * @param sPkcs11Provider The PKCS #11 provider
     * @return True if a keystore is opened, false otherwise
     */
    /* package private */boolean openKeyStorePkcs11(String sPkcs11Provider)
    {
        // Get the user to enter the keystore's password
        DGetPassword dGetPassword = new DGetPassword(this,
            MessageFormat.format(
                m_res.getString("FPortecle.GetKeyStorePassword.Title"),
                new String[] { sPkcs11Provider }), true);
        dGetPassword.setLocationRelativeTo(this);
        dGetPassword.setVisible(true);
        char[] cPassword = dGetPassword.getPassword();

        if (cPassword == null) {
            return false;
        }

        // Load the keystore
        KeyStore openedKeyStore = null;

        try {
            openedKeyStore = KeyStoreUtil.loadKeyStore(sPkcs11Provider,
                cPassword);
            m_keyStoreWrap = new KeyStoreWrapper(openedKeyStore, null,
                cPassword);
        }
        catch (CryptoException e) {
            int iSelected = JOptionPane.showConfirmDialog(this,
                MessageFormat.format(
                    m_res.getString("FPortecle.NoOpenKeyStorePkcs11.message"),
                    new Object[] { sPkcs11Provider }),
                m_res.getString("FPortecle.ChoosePkcs11Provider.Title"),
                JOptionPane.YES_NO_OPTION);
            if (iSelected == JOptionPane.YES_OPTION) {
                displayException(e);
            }
            return false;
        }

        // Update the frame's components and title
        updateControls();
        updateTitle();

        return true;
    }

    /**
     * Save the currently opened keystore back to the file it was originally
     * opened from.
     *
     * @return True if the keystore is saved to disk, false otherwise
     */
    /* package private */boolean saveKeyStore()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // File to save to
        File fSaveFile = m_keyStoreWrap.getKeyStoreFile();

        // Not saved before - use Save As
        if (fSaveFile == null) {
            return saveKeyStoreAs();
        }

        // Get the password to protect the keystore with
        char[] cPassword = m_keyStoreWrap.getPassword();

        // No password set for keystore - get one from the user
        if (cPassword == null) {
            cPassword = getNewKeyStorePassword();

            // User cancelled - cancel save
            if (cPassword == null) {
                return false;
            }
        }

        try {
            // Do the save
            m_keyStoreWrap.setKeyStore(
                KeyStoreUtil.saveKeyStore(m_keyStoreWrap.getKeyStore(),
                    fSaveFile, cPassword));

            // Update the keystore wrapper
            m_keyStoreWrap.setPassword(cPassword);
            m_keyStoreWrap.setKeyStoreFile(fSaveFile);
            m_keyStoreWrap.setChanged(false);

            // Update the frame's components and title
            updateControls();
            updateTitle();

            return true;
        }
        catch (FileNotFoundException ex) {
            JOptionPane.showMessageDialog(this, MessageFormat.format(
                m_res.getString("FPortecle.NoWriteFile.message"),
                new Object[] { fSaveFile }),
                m_res.getString("FPortecle.SaveKeyStore.Title"),
                JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (Exception ex) {
            displayException(ex);
            return false;
        }
    }

    /**
     * Get a new keystore password.
     *
     * @return The new keystore password
     */
    private char[] getNewKeyStorePassword()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // Display the get new password dialog
        DGetNewPassword dGetNewPassword = new DGetNewPassword(this,
            m_res.getString("FPortecle.SetKeyStorePassword.Title"), true);
        dGetNewPassword.setLocationRelativeTo(this);
        dGetNewPassword.setVisible(true);

        // Dialog returned - retrieve the password and return it
        char[] cPassword = dGetNewPassword.getPassword();

        return cPassword;
    }

    /**
     * Save the currently opened keystore to disk to what may be a different
     * file from the one it was opened from (if any).
     *
     * @return True if the keystore is saved to disk, false otherwise
     */
    private boolean saveKeyStoreAs()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // Keystore's current password
        char[] cPassword = m_keyStoreWrap.getPassword();

        // Get a new password if this keystore exists in another file or is an
        // unsaved keystore for which no password has been set yet
        if (m_keyStoreWrap.getKeyStoreFile() != null
            || (m_keyStoreWrap.getKeyStoreFile() == null && cPassword == null))
        {
            cPassword = getNewKeyStorePassword();

            if (cPassword == null) {
                return false;
            }
        }

        // Let the user choose a save file
        JFileChooser chooser = FileChooserFactory.getKeyStoreFileChooser(
            m_keyStoreWrap.getKeyStoreType());
       
        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FPortecle.SaveKeyStoreAs.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showSaveDialog(this);
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            File fSaveFile = chooser.getSelectedFile();

            try {
                if (!confirmOverwrite(fSaveFile,
                    m_res.getString("FPortecle.SaveKeyStoreAs.Title")))
                {
                    return false;
                }

                // Save the keystore to file
                m_keyStoreWrap.setKeyStore(
                    KeyStoreUtil.saveKeyStore(m_keyStoreWrap.getKeyStore(),
                        fSaveFile, cPassword));

                // Update the keystore wrapper
                m_keyStoreWrap.setPassword(cPassword);
                m_keyStoreWrap.setKeyStoreFile(fSaveFile);
                m_keyStoreWrap.setChanged(false);

                // Update the frame's components and title
                updateControls();
                updateTitle();

                // Add keystore file to recent files in file menu
                m_jmrfFile.add(createRecentFileMenuItem(fSaveFile));

                m_lastDir.updateLastDir(fSaveFile);

                return true;
            }
            catch (FileNotFoundException ex) {
                JOptionPane.showMessageDialog(this, MessageFormat.format(
                    m_res.getString("FPortecle.NoWriteFile.message"),
                    new Object[] { fSaveFile }),
                    m_res.getString("FPortecle.SaveKeyStoreAs.Title"),
                    JOptionPane.WARNING_MESSAGE);
                return false;
            }
            catch (Exception ex) {
                displayException(ex);
                return false;
            }
        }
        return false;
    }

    /**
     * Check if the currently opened keystore requires to be saved.
     *
     * @return True if the keystore has been changed since the last open/save,
     * false otherwise
     */
    /* package private */boolean needSave()
    {
        boolean bNeedSave = false;

        if (m_keyStoreWrap != null) {
            if (m_keyStoreWrap.isChanged()) {
                bNeedSave = true;
            }
        }
        return bNeedSave;
    }

    /**
     * Ask the user if they want to save the current keystore file.
     *
     * @return JOptionPane.YES_OPTION, JOptionPane.NO_OPTION or
     * JOptionPane.CANCEL_OPTION; JOptionPane.CLOSED_OPTION is reported
     * as JOptionPane.CANCEL_OPTION
     */
    /* package private */int wantSave()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        File fKeyStoreFile = m_keyStoreWrap.getKeyStoreFile();
        String sKeyStoreName;

        if (fKeyStoreFile != null) {
            sKeyStoreName = fKeyStoreFile.getName();
        }
        else {
            sKeyStoreName = m_res.getString("FPortecle.Untitled");
        }

        String sMessage = MessageFormat.format(
            m_res.getString("FPortecle.WantSaveChanges.message"),
            new String[] { sKeyStoreName });

        int iSelected = JOptionPane.showConfirmDialog(this, sMessage,
            m_res.getString("FPortecle.WantSaveChanges.Title"),
            JOptionPane.YES_NO_CANCEL_OPTION);
        if (iSelected == JOptionPane.CLOSED_OPTION) {
            iSelected = JOptionPane.CANCEL_OPTION;
        }
        return iSelected;
    }

    /**
     * Create a new keystore file.
     *
     * @return True is a new keystore file is created, false otherwise
     */
    private boolean newKeyStore()
    {
        // Does the current keystore contain unsaved changes?
        if (needSave()) {
            // Yes - ask the user if it should be saved
            int iWantSave = wantSave();

            if (iWantSave == JOptionPane.YES_OPTION) {
                // Save it
                if (!saveKeyStore()) {
                    return false;
                }
            }
            else if (iWantSave == JOptionPane.CANCEL_OPTION) {
                return false;
            }
        }

        try {
            // Ask user for keystore type
            DNewKeyStoreType dNewKeyStoreType = new DNewKeyStoreType(this,
                true);
            dNewKeyStoreType.setLocationRelativeTo(this);
            dNewKeyStoreType.setVisible(true);

            KeyStoreType keyStoreType = dNewKeyStoreType.getKeyStoreType();

            // No keystore type chosen
            if (keyStoreType == null) {
                return false;
            }

            // Create new keystore
            KeyStore newKeyStore = KeyStoreUtil.createKeyStore(keyStoreType);

            // Update the keystore wrapper
            m_keyStoreWrap = new KeyStoreWrapper(newKeyStore);
            m_keyStoreWrap.setChanged(true);

            // Update the frame's components and title
            updateControls();
            updateTitle();

            return true;
        }
        catch (Exception ex) {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user examine the contents of a certificate file.
     *
     * @return True if the user was able to examine the certificate file,
     * false otherwise
     */
    private boolean examineCert()
    {
        // Let the user choose the certificate file to examine
        File fCertFile = chooseExamineCertFile();
        if (fCertFile == null) {
            return false;
        }

        // Get the certificates contained within the file
        X509Certificate[] certs = openCert(fCertFile);

        m_lastDir.updateLastDir(fCertFile);

        try {
            // If there are any display the view certificate dialog with them
            if (certs != null && certs.length != 0) {
                DViewCertificate dViewCertificate = new DViewCertificate(this,
                    MessageFormat.format(
                        m_res.getString("FPortecle.CertDetailsFile.Title"),
                        new String[] { fCertFile.getName() }), true, certs);
                dViewCertificate.setLocationRelativeTo(this);
                dViewCertificate.setVisible(true);
                return true;
            }
            return false;
        }
        catch (CryptoException ex) {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user examine the contents of a certificate file from a SSL
     * connection.
     *
     * @return True if the user was able to examine the certificate,
     * false otherwise
     */
    private boolean examineCertSSL()
    {
        InetSocketAddress ia = chooseExamineCertSSL();
        if (ia == null) {
            return false;
        }

        // TODO: options from user
        boolean bVerifyCerts = false;
        int timeOut = 10000;

        // Get the certificates received from the connection
        X509Certificate[] certs = null;
        SSLSocket ss = null;

        try {

            SSLSocketFactory sf;
            if (bVerifyCerts) {
                sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
            }
            else {
                // @@@TODO: cache all this?
                SSLContext sc = SSLContext.getInstance("SSL");
                X509TrustManager[] tm = { new X509TrustManager()
                {
                    public void checkClientTrusted(X509Certificate[] chain,
                        String authType)
                    {
                    }

                    public void checkServerTrusted(X509Certificate[] chain,
                        String authType)
                    {
                    }

                    public X509Certificate[] getAcceptedIssuers()
                    {
                        return new X509Certificate[0];
                    }
                } };
                if (m_rnd == null) {
                    m_rnd = new SecureRandom();
                }
                sc.init(null, tm, m_rnd);
                sf = sc.getSocketFactory();
            }

            ss = (SSLSocket) sf.createSocket();
            ss.setSoTimeout(timeOut);
            ss.connect(ia, timeOut);
            SSLSession sess = ss.getSession();
            // @@@TODO: fails with GNU Classpath: http://gcc.gnu.org/bugzilla/show_bug.cgi?id=29692
            certs = (X509Certificate[]) sess.getPeerCertificates();
            sess.invalidate();
        }
        catch (Exception e) {
            displayException(e);
            return false;
        }
        finally {
            if (ss != null && !ss.isClosed()) {
                try {
                    ss.close();
                }
                catch (IOException e) {
                    displayException(e);
                }
            }
        }

        // Check what we got

        try {
            // If there are any display the view certificate dialog with them
            if (certs != null && certs.length != 0) {
                DViewCertificate dViewCertificate = new DViewCertificate(
                    this,
                    MessageFormat.format(
                        m_res.getString("FPortecle.CertDetailsSSL.Title"),
                        new String[] { ia.getHostName() + ":" + ia.getPort() }),
                    true, certs);
                dViewCertificate.setLocationRelativeTo(this);
                dViewCertificate.setVisible(true);
                return true;
            }
            return false;
        }
        catch (CryptoException ex) {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user examine the contents of a CSR file.
     *
     * @return True if the user was able to examine the CSR file,
     * false otherwise
     */
    private boolean examineCSR()
    {
        // Let the user choose the certificate file to examine
        File fCSRFile = chooseExamineCSRFile();
        if (fCSRFile == null) {
            return false;
        }

        // Get the CSR contained within the file
        PKCS10CertificationRequest csr = openCSR(fCSRFile);

        m_lastDir.updateLastDir(fCSRFile);

        // If a CSR is available then diaply the view CSR dialog with it
        if (csr != null) {
            try {
                DViewCSR dViewCSR = new DViewCSR(this, MessageFormat.format(
                    m_res.getString("FPortecle.CsrDetailsFile.Title"),
                    new String[] { fCSRFile.getName() }), true, csr);
                dViewCSR.setLocationRelativeTo(this);
                dViewCSR.setVisible(true);
                return true;
            }
            catch (CryptoException e) {
                displayException(e);
            }
        }
        return false;
    }

    /**
     * Let the user examine the contents of a CRL file.
     *
     * @return True if the user was able to examine the CRL file,
     * false otherwise
     */
    private boolean examineCRL()
    {
        // Let the user choose the certificate file to examine
        File fCRLFile = chooseExamineCRLFile();
        if (fCRLFile == null) {
            return false;
        }

        // Get the CRL contained within the file
        X509CRL crl = openCRL(fCRLFile);

        m_lastDir.updateLastDir(fCRLFile);

        // If a CRL is available then diaply the view CRL dialog with it
        if (crl != null) {
            DViewCRL dViewCRL = new DViewCRL(this, MessageFormat.format(
                m_res.getString("FPortecle.CrlDetailsFile.Title"),
                new String[] { fCRLFile.getName() }), true, crl);
            dViewCRL.setLocationRelativeTo(this);
            dViewCRL.setVisible(true);
            return true;
        }
        return false;
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
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FPortecle.ImportCaReply.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this,
            m_res.getString("FPortecle.ImportCaReply.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
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
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FPortecle.ExamineCertificate.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this,
            m_res.getString("FPortecle.ExamineCertificate.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            File fOpenFile = chooser.getSelectedFile();
            return fOpenFile;
        }
        return null;
    }

    /**
     * Let the user choose a certificate to examine from a SSL connection.
     *
     * @return The chosen inet address or null if none was chosen
     */
    private InetSocketAddress chooseExamineCertSSL()
    {
        DGetHostPort d = new DGetHostPort(this,
            m_res.getString("FPortecle.ExamineCertificateSSL.Title"), true,
            null);
        d.setLocationRelativeTo(this);
        d.setVisible(true);
        return d.getHostPort();
    }

    /**
     * Let the user choose a CSR file to examine.
     *
     * @return The chosen file or null if none was chosen
     */
    private File chooseExamineCSRFile()
    {
        JFileChooser chooser = FileChooserFactory.getCsrFileChooser(null);

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FPortecle.ExamineCsr.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this,
            m_res.getString("FPortecle.ExamineCsr.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
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
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FPortecle.ExamineCrl.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this,
            m_res.getString("FPortecle.ExamineCrl.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
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

        JFileChooser chooser = FileChooserFactory.getX509FileChooser(null);

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FPortecle.ImportTrustCert.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this,
            m_res.getString("FPortecle.ImportTrustCert.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            File fImportFile = chooser.getSelectedFile();
            return fImportFile;
        }
        return null;
    }

    /**
     * Let the user choose a PKCS #12 keystore file to import from.
     *
     * @return The chosen file or null if none was chosen
     */
    private File chooseImportPkcs12File()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        JFileChooser chooser = FileChooserFactory.getPkcs12FileChooser(null);

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FPortecle.ImportPkcs12KeyStore.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this,
            m_res.getString("FPortecle.ImportPkcs12KeyStore.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            File fPkcs12File = chooser.getSelectedFile();
            return fPkcs12File;
        }
        return null;
    }

    /**
     * Let the user choose a file to generate a CSR in.
     *
     * @param basename default filename (without extension)
     * @return The chosen file or null if none was chosen
     */
    private File chooseGenerateCsrFile(String basename)
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        JFileChooser chooser = FileChooserFactory.getCsrFileChooser(basename);

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FPortecle.GenerateCsr.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this,
            m_res.getString("FPortecle.GenerateCsr.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
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
        try {
            X509Certificate[] certs = null;
            String[] certTypes = { X509CertUtil.PKCS7_ENCODING,
                X509CertUtil.PKIPATH_ENCODING, null,
                X509CertUtil.OPENSSL_PEM_ENCODING, };
            Exception[] exs = new Exception[certTypes.length];
            for (int iCnt = 0; iCnt < certTypes.length; iCnt++) {
                try {
                    certs = X509CertUtil.loadCertificates(fCertFile,
                        certTypes[iCnt]);
                    break; // Success!
                }
                catch (Exception ex) {
                    exs[iCnt] = ex;
                }
            }

            if (certs == null) {
                // None of the types worked - show each of the errors?
                int iSelected = JOptionPane.showConfirmDialog(
                    this,
                    MessageFormat.format(
                        m_res.getString("FPortecle.NoOpenCertificate.message"),
                        new Object[] { fCertFile }),
                    m_res.getString("FPortecle.OpenCertificate.Title"),
                    JOptionPane.YES_NO_OPTION);
                if (iSelected == JOptionPane.YES_OPTION) {
                    for (int iCnt = 0; iCnt < exs.length; iCnt++) {
                        displayException(exs[iCnt]);
                    }
                }
            }
            else if (certs.length == 0) {
                JOptionPane.showMessageDialog(this, MessageFormat.format(
                    m_res.getString("FPortecle.NoCertsFound.message"),
                    new Object[] { fCertFile }),
                    m_res.getString("FPortecle.OpenCertificate.Title"),
                    JOptionPane.WARNING_MESSAGE);
            }

            return certs;
        }
        catch (Exception ex) {
            displayException(ex);
            return null;
        }
    }

    /**
     * Open a CSR file.
     *
     * @param fCSRFile The CSR file
     * @return The CSR found in the file or null if there wasn't one
     */
    private PKCS10CertificationRequest openCSR(File fCSRFile)
    {
        try {
            return X509CertUtil.loadCSR(fCSRFile);
        }
        catch (FileNotFoundException ex) {
            JOptionPane.showMessageDialog(this, MessageFormat.format(
                m_res.getString("FPortecle.NoReadFile.message"),
                new Object[] { fCSRFile }), MessageFormat.format(
                m_res.getString("FPortecle.CsrDetailsFile.Title"),
                new String[] { fCSRFile.getName() }),
                JOptionPane.WARNING_MESSAGE);
            return null;
        }
        catch (Exception ex) {
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
        try {
            X509CRL crl = X509CertUtil.loadCRL(fCRLFile);
            return crl;
        }
        catch (FileNotFoundException ex) {
            JOptionPane.showMessageDialog(this, MessageFormat.format(
                m_res.getString("FPortecle.NoReadFile.message"),
                new Object[] { fCRLFile }), MessageFormat.format(
                m_res.getString("FPortecle.CrlDetailsFile.Title"),
                new String[] { fCRLFile.getName() }),
                JOptionPane.WARNING_MESSAGE);
            return null;
        }
        catch (Exception ex) {
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

        if (iRow == -1) {
            return false;
        }

        String sAlias = (String) m_jtKeyStore.getValueAt(iRow, 1);

        // Get the keystore
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        // Let the user choose a file for the trusted certificate
        File fCertFile = chooseImportCAFile();
        if (fCertFile == null) {
            return false;
        }

        // Load the certificate(s)
        X509Certificate[] certs = openCert(fCertFile);

        if (certs == null || certs.length == 0) {
            return false;
        }

        try {
            // Order the new certificates into a chain...
            certs = X509CertUtil.orderX509CertChain(certs);

            // ...and those that exist in the entry already
            X509Certificate[] oldCerts = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(keyStore.getCertificateChain(sAlias)));

            // Compare the public keys of the start of each chain
            if (!oldCerts[0].getPublicKey().equals(certs[0].getPublicKey())) {
                JOptionPane.showMessageDialog(this,
                    m_res.getString("FPortecle.NoMatchPubKeyCaReply.message"),
                    m_res.getString("FPortecle.ImportCaReply.Title"),
                    JOptionPane.ERROR_MESSAGE);
                return false;
            }

            // If the CA certs keystore is to be used and it has yet to
            // be loaded then do so
            if (m_bUseCaCerts && m_caCertsKeyStore == null) {
                m_caCertsKeyStore = openCaCertsKeyStore();
                if (m_caCertsKeyStore == null) {
                    // Failed to load CA certs keystore
                    return false;
                }
            }

            // Holds the new certificate chain for the entry should the
            // import succeed
            X509Certificate[] newCertChain = null;

            /* PKCS #7 reply - try and match the self-signed root with any of
             the certificates in the CA certs or current keystore */
            if (certs.length > 1) {
                X509Certificate rootCert = certs[certs.length - 1];
                String sMatchAlias = null;

                if (m_bUseCaCerts) // Match against CA certs keystore
                {
                    sMatchAlias = X509CertUtil.matchCertificate(
                        m_caCertsKeyStore, rootCert);
                }

                if (sMatchAlias == null) // Match against current keystore
                {
                    sMatchAlias = X509CertUtil.matchCertificate(keyStore,
                        rootCert);
                }

                // No match
                if (sMatchAlias == null) {
                    // Tell the user what is happening
                    JOptionPane.showMessageDialog(
                        this,
                        m_res.getString("FPortecle.NoMatchRootCertCaReplyConfirm.message"),
                        m_res.getString("FPortecle.ImportCaReply.Title"),
                        JOptionPane.INFORMATION_MESSAGE);

                    // Display the certficate to the user
                    DViewCertificate dViewCertificate = new DViewCertificate(
                        this,
                        MessageFormat.format(
                            m_res.getString("FPortecle.CertDetailsFile.Title"),
                            new String[] { fCertFile.getName() }), true,
                        new X509Certificate[] { rootCert });
                    dViewCertificate.setLocationRelativeTo(this);
                    dViewCertificate.setVisible(true);

                    // Request confirmation that the certidicate is to
                    // be trusted
                    int iSelected = JOptionPane.showConfirmDialog(this,
                        m_res.getString("FPortecle.AcceptCaReply.message"),
                        m_res.getString("FPortecle.ImportCaReply.Title"),
                        JOptionPane.YES_NO_OPTION);
                    if (iSelected != JOptionPane.YES_OPTION) {
                        return false;
                    }
                    newCertChain = certs;
                }
                else {
                    newCertChain = certs;
                }
            }
            /* Single X.509 certificate reply - try and establish a chain of
             trust from the certificate and ending with a root CA self-signed
             certificate */
            else {
                KeyStore[] compKeyStores = null;

                // Establish against CA certs keystore and current keystore
                if (m_bUseCaCerts) {
                    compKeyStores = new KeyStore[] { m_caCertsKeyStore,
                        keyStore };
                }
                else // Establish against current keystore only
                {
                    compKeyStores = new KeyStore[] { keyStore };
                }

                X509Certificate[] trustChain = X509CertUtil.establishTrust(
                    compKeyStores, certs[0]);

                if (trustChain != null) {
                    newCertChain = trustChain;
                }
                else {
                    JOptionPane.showMessageDialog(this,
                        m_res.getString("FPortecle.NoTrustCaReply.message"),
                        m_res.getString("FPortecle.ImportCaReply.Title"),
                        JOptionPane.ERROR_MESSAGE);
                    return false;
                }
            }

            // Get the entry's password (we may already know it from the
            // wrapper)
            char[] cPassword = m_keyStoreWrap.getEntryPassword(sAlias);

            if (cPassword == null) {
                cPassword = PKCS12_DUMMY_PASSWORD;

                // Password is only relevant if the keystore is not PKCS #12
                if (!keyStore.getType().equals(KeyStoreType.PKCS12.toString()))
                {
                    DGetPassword dGetPassword = new DGetPassword(this,
                        m_res.getString("FPortecle.KeyEntryPassword.Title"),
                        true);
                    dGetPassword.setLocationRelativeTo(this);
                    dGetPassword.setVisible(true);
                    cPassword = dGetPassword.getPassword();

                    if (cPassword == null) {
                        return false;
                    }
                }
            }

            // Replace the certificate chain
            Key privKey = keyStore.getKey(sAlias, cPassword);
            keyStore.deleteEntry(sAlias);
            keyStore.setKeyEntry(sAlias, privKey, cPassword, newCertChain);

            // Update the keystore wrapper
            m_keyStoreWrap.setChanged(true);
            m_keyStoreWrap.setEntryPassword(sAlias, cPassword);

            // Update the frame's components and title
            updateControls();
            updateTitle();

            m_lastDir.updateLastDir(fCertFile);

            // Display success message
            JOptionPane.showMessageDialog(this,
                m_res.getString("FPortecle.ImportCaReplySuccessful.message"),
                m_res.getString("FPortecle.ImportCaReply.Title"),
                JOptionPane.INFORMATION_MESSAGE);

            return true;
        }
        catch (Exception ex) {
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
        if (fCertFile == null) {
            return false;
        }

        // Load the certificate(s)
        X509Certificate[] certs = openCert(fCertFile);

        if (certs == null || certs.length == 0) {
            return false;
        }

        if (certs.length > 1) {
            // Cannot import more than one certificate
            JOptionPane.showMessageDialog(
                this,
                m_res.getString("FPortecle.NoMultipleTrustCertImport.message"),
                m_res.getString("FPortecle.ImportTrustCert.Title"),
                JOptionPane.ERROR_MESSAGE);
            return false;
        }

        X509Certificate trustCert = certs[0];

        try {
            // Get the keystore
            KeyStore keyStore = m_keyStoreWrap.getKeyStore();

            // Certificate already exists in the keystore
            String sMatchAlias = X509CertUtil.matchCertificate(keyStore,
                trustCert);
            if (sMatchAlias != null) {
                int iSelected = JOptionPane.showConfirmDialog(
                    this,
                    MessageFormat.format(
                        m_res.getString("FPortecle.TrustCertExistsConfirm.message"),
                        new String[] { sMatchAlias }),
                    m_res.getString("FPortecle.ImportTrustCert.Title"),
                    JOptionPane.YES_NO_OPTION);
                if (iSelected != JOptionPane.YES_OPTION) {
                    return false;
                }
            }

            // If the CA certs keystore is to be used and it has yet to be
            // loaded then do so
            if (m_bUseCaCerts && m_caCertsKeyStore == null) {
                m_caCertsKeyStore = openCaCertsKeyStore();
                if (m_caCertsKeyStore == null) {
                    // Failed to load CA certs keystore
                    return false;
                }
            }

            // If we cannot establish trust for the certificate against the
            // CA certs keystore or the current keystore then display the
            // certificate to the user for confirmation
            KeyStore[] compKeyStores = null;

            // Establish against CA certs keystore and current keystore
            if (m_bUseCaCerts) {
                compKeyStores = new KeyStore[] { m_caCertsKeyStore, keyStore };
            }
            else // Establish against current keystore only
            {
                compKeyStores = new KeyStore[] { keyStore };
            }

            if (X509CertUtil.establishTrust(compKeyStores, trustCert) == null)
            {
                // Tell the user what is happening
                JOptionPane.showMessageDialog(
                    this,
                    m_res.getString("FPortecle.NoTrustPathCertConfirm.message"),
                    m_res.getString("FPortecle.ImportTrustCert.Title"),
                    JOptionPane.INFORMATION_MESSAGE);

                // Display the certficate to the user
                DViewCertificate dViewCertificate = new DViewCertificate(this,
                    MessageFormat.format(
                        m_res.getString("FPortecle.CertDetailsFile.Title"),
                        new String[] { fCertFile.getName() }), true,
                    new X509Certificate[] { trustCert });
                dViewCertificate.setLocationRelativeTo(this);
                dViewCertificate.setVisible(true);

                // Request confirmation that the certidicate is to be trusted
                int iSelected = JOptionPane.showConfirmDialog(this,
                    m_res.getString("FPortecle.AcceptTrustCert.message"),
                    m_res.getString("FPortecle.ImportTrustCert.Title"),
                    JOptionPane.YES_NO_OPTION);
                if (iSelected != JOptionPane.YES_OPTION) {
                    return false;
                }
            }

            // Get the entry alias to put the trusted certificate into
            DGetAlias dGetAlias = new DGetAlias(this,
                m_res.getString("FPortecle.TrustCertEntryAlias.Title"), true,
                X509CertUtil.getCertificateAlias(trustCert).toLowerCase());
            dGetAlias.setLocationRelativeTo(this);
            dGetAlias.setVisible(true);
            String sAlias = dGetAlias.getAlias();

            if (sAlias == null) {
                return false;
            }

            // Check entry does not already exist in the keystore
            if (keyStore.containsAlias(sAlias)) {
                String sMessage = MessageFormat.format(
                    m_res.getString("FPortecle.OverWriteEntry.message"),
                    new String[] { sAlias });

                int iSelected = JOptionPane.showConfirmDialog(this, sMessage,
                    m_res.getString("FPortecle.ImportTrustCert.Title"),
                    JOptionPane.YES_NO_OPTION);
                if (iSelected != JOptionPane.YES_OPTION) {
                    return false;
                }
                // Otherwise carry on - delete entry to be copied over
                keyStore.deleteEntry(sAlias);
            }

            // Import the trusted certificate
            keyStore.setCertificateEntry(sAlias, trustCert);

            // Update the keystore wrapper
            m_keyStoreWrap.setChanged(true);

            // Update the frame's components and title
            updateControls();
            updateTitle();

            m_lastDir.updateLastDir(fCertFile);

            // Display success message
            JOptionPane.showMessageDialog(
                this,
                m_res.getString("FPortecle.ImportTrustCertSuccessful.message"),
                m_res.getString("FPortecle.ImportTrustCert.Title"),
                JOptionPane.INFORMATION_MESSAGE);

            return true;
        }
        catch (Exception ex) {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user import a key pair from a PKCS #12 keystore.
     *
     * @return True if the import is successful, false otherwise
     */
    private boolean importKeyPair()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        // Let the user choose a a PKCS #12 keystore file
        File fPkcs12 = chooseImportPkcs12File();
        if (fPkcs12 == null) {
            return false;
        }

        // The PKCS #12 file is not a file
        if (!fPkcs12.isFile()) {
            JOptionPane.showMessageDialog(this, MessageFormat.format(
                m_res.getString("FPortecle.NotFile.message"),
                new Object[] { fPkcs12 }),
                m_res.getString("FPortecle.ImportKeyPair.Title"),
                JOptionPane.WARNING_MESSAGE);
            return false;
        }

        // Get the user to enter the PKCS #12 keystore's password
        DGetPassword dGetPassword = new DGetPassword(this,
            m_res.getString("FPortecle.Pkcs12Password.Title"), true);
        dGetPassword.setLocationRelativeTo(this);
        dGetPassword.setVisible(true);
        char[] cPkcs12Password = dGetPassword.getPassword();

        if (cPkcs12Password == null) {
            return false;
        }

        try {
            // Load the PKCS #12 keystore
            KeyStore pkcs12 = KeyStoreUtil.loadKeyStore(fPkcs12,
                cPkcs12Password, KeyStoreType.PKCS12);

            m_lastDir.updateLastDir(fPkcs12);

            // Display the import key pair dialog supplying the PKCS #12
            // keystore to it
            DImportKeyPair dImportKeyPair = new DImportKeyPair(this, true,
                pkcs12);
            dImportKeyPair.setLocationRelativeTo(this);
            dImportKeyPair.setVisible(true);

            // Get the private key and certificate chain of the key pair
            Key privateKey = dImportKeyPair.getPrivateKey();
            Certificate[] certs = dImportKeyPair.getCertificateChain();

            if (privateKey == null || certs == null) {
                // User did not select a key pair for import
                return false;
            }

            // Get an alias for the new keystore entry
            String sAlias = dImportKeyPair.getAlias();
            if (sAlias == null) {
                sAlias = X509CertUtil.getCertificateAlias(X509CertUtil.convertCertificate(certs[0]));
            }

            // Get the alias for the new key pair entry
            DGetAlias dGetAlias = new DGetAlias(this,
                m_res.getString("FPortecle.KeyPairEntryAlias.Title"), true,
                sAlias.toLowerCase());
            dGetAlias.setLocationRelativeTo(this);
            dGetAlias.setVisible(true);
            sAlias = dGetAlias.getAlias();

            if (sAlias == null) {
                return false;
            }

            // Alias to possibly delete before adding new one
            String sAliasToDelete = null;

            // Check an entry with the selected does not already exist
            // in the keystore
            if (keyStore.containsAlias(sAlias)) {
                String sMessage = MessageFormat.format(
                    m_res.getString("FPortecle.OverWriteEntry.message"),
                    new String[] { sAlias });

                int iSelected = JOptionPane.showConfirmDialog(this, sMessage,
                    m_res.getString("FPortecle.KeyPairEntryAlias.Title"),
                    JOptionPane.YES_NO_OPTION);
                if (iSelected != JOptionPane.YES_OPTION) {
                    return false;
                }
                // Otherwise carry on - delete old entry later
                sAliasToDelete = sAlias;
            }

            // Get a password for the new keystore entry (only relevant if
            // the keystore is not PKCS #12)
            char[] cPassword = PKCS12_DUMMY_PASSWORD;

            if (!keyStore.getType().equals(KeyStoreType.PKCS12.toString())) {
                DGetNewPassword dGetNewPassword = new DGetNewPassword(this,
                    m_res.getString("FPortecle.KeyEntryPassword.Title"), true);
                dGetNewPassword.setLocationRelativeTo(this);
                dGetNewPassword.setVisible(true);
                cPassword = dGetNewPassword.getPassword();

                if (cPassword == null) {
                    return false;
                }
            }
            
            // If needed, delete old entry first
            if (sAliasToDelete != null) {
                keyStore.deleteEntry(sAliasToDelete);
            }

            // Place the private key and certificate chain into the keystore
            // and update the keystore wrapper
            keyStore.setKeyEntry(sAlias, privateKey, cPassword, certs);
            m_keyStoreWrap.setEntryPassword(sAlias, cPassword);
            m_keyStoreWrap.setChanged(true);

            // Update the frame's components and title
            updateControls();
            updateTitle();

            // Display success message
            JOptionPane.showMessageDialog(this,
                m_res.getString("FPortecle.KeyPairImportSuccessful.message"),
                m_res.getString("FPortecle.ImportKeyPair.Title"),
                JOptionPane.INFORMATION_MESSAGE);
            return true;
        }
        catch (Exception ex) {
            displayException(ex);
            return false;
        }
    }

    /**
     * Open the CA certs keystore from disk.
     *
     * @return The keystore if it could be openend or null otherwise
     */
    private KeyStore openCaCertsKeyStore()
    {
        // Get the user to enter the CA certs keystore's password
        DGetPassword dGetPassword = new DGetPassword(this,
            m_res.getString("FPortecle.CaCertsKeyStorePassword.Title"), true);
        dGetPassword.setLocationRelativeTo(this);
        dGetPassword.setVisible(true);
        char[] cPassword = dGetPassword.getPassword();

        if (cPassword == null) {
            return null;
        }

        try {
            // Load the CA certs keystore - try to open as each of the
            // allowed types in turn until successful
            KeyStore caCertsKeyStore = null;

            // Types
            KeyStoreType[] keyStoreTypes = KeyStoreUtil.getAvailableTypes();

            // Exceptions
            CryptoException[] cexs = new CryptoException[keyStoreTypes.length];

            // Tried types
            StringBuffer tried = new StringBuffer();
            
            for (int iCnt = 0; iCnt < keyStoreTypes.length; iCnt++) {
                tried.append(", ").append(keyStoreTypes[iCnt].toPrettyString());
                try {
                    caCertsKeyStore = KeyStoreUtil.loadKeyStore(
                        m_fCaCertsFile, cPassword, keyStoreTypes[iCnt]);
                    break; // Success
                }
                catch (CryptoException cex) {
                    cexs[iCnt] = cex;
                }
            }

            if (caCertsKeyStore == null) {
                // None of the types worked - show each of the errors?
                if (tried.length() > 2) {
                    tried.delete(0, 2); // Chop leading ", "
                }
                int iSelected = JOptionPane.showConfirmDialog(
                    this,
                    MessageFormat.format(
                        m_res.getString("FPortecle.NoOpenCaCertsKeyStore.message"),
                        new Object[] { m_fCaCertsFile, tried }),
                    m_res.getString("FPortecle.OpenCaCertsKeyStore.Title"),
                    JOptionPane.YES_NO_OPTION);
                if (iSelected == JOptionPane.YES_OPTION) {
                    for (int iCnt = 0; iCnt < cexs.length; iCnt++) {
                        displayException(cexs[iCnt]);
                    }
                }

                return null;
            }

            return caCertsKeyStore;
        }
        catch (FileNotFoundException ex) {
            JOptionPane.showMessageDialog(this, MessageFormat.format(
                m_res.getString("FPortecle.NoReadFile.message"),
                new Object[] { m_fCaCertsFile }),
                m_res.getString("FPortecle.OpenCaCertsKeyStore.Title"),
                JOptionPane.WARNING_MESSAGE);
            return null;
        }
        catch (Exception ex) {
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
        if (m_fHelp == null) {
            URL toc = FPortecle.class.getResource(
                m_res.getString("FPortecle.Help.Contents"));
            URL home = FPortecle.class.getResource(
                m_res.getString("FPortecle.Help.Home"));

            m_fHelp = new FHelp(m_res.getString("FPortecle.Help.Title"), home,
                toc);
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
        String sWebsiteAddress = m_res.getString("FPortecle.WebsiteAddress");

        try {
            BrowserLauncher.openURL(sWebsiteAddress);
        }
        catch (IOException ex) {
            // Could not launch web browser - tell the user the address
            JOptionPane.showMessageDialog(this, MessageFormat.format(
                m_res.getString("FPortecle.NoLaunchBrowser.message"),
                new String[] { sWebsiteAddress }),
                m_res.getString("FPortecle.Title"),
                JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * Display Portecle project page at SourceForge.net.
     */
    private void visitSFNetProject()
    {
        String sWebsiteAddress = m_res.getString("FPortecle.SFNetProjectAddress");

        try {
            BrowserLauncher.openURL(sWebsiteAddress);
        }
        catch (IOException ex) {
            // Could not launch web browser - tell the user the address
            JOptionPane.showMessageDialog(this, MessageFormat.format(
                m_res.getString("FPortecle.NoLaunchBrowser.message"),
                new String[] { sWebsiteAddress }),
                m_res.getString("FPortecle.Title"),
                JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * Compose email to application author.
     */
    private void composeEmail()
    {
        String sEmailAddress = m_res.getString("FPortecle.EmailAddress");

        try {
            BrowserLauncher.openURL("mailto:" + sEmailAddress);
        }
        catch (IOException ex) {
            // Could not launch email client - tell the user the address
            JOptionPane.showMessageDialog(this, MessageFormat.format(
                m_res.getString("FPortecle.NoLaunchEmail.message"),
                new String[] { sEmailAddress }),
                m_res.getString("FPortecle.Title"),
                JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * Display Portecle mailing lists' signup page at SourceForge.net.
     */
    private void visitMailListSignup()
    {
        String sMailListSignupAddress = m_res.getString("FPortecle.MailListSignupAddress");

        try {
            BrowserLauncher.openURL(sMailListSignupAddress);
        }
        catch (IOException ex) {
            // Could not launch web browser - tell the user the address
            JOptionPane.showMessageDialog(this, MessageFormat.format(
                m_res.getString("FPortecle.NoLaunchBrowser.message"),
                new String[] { sMailListSignupAddress }),
                m_res.getString("FPortecle.Title"),
                JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * Check if a more up-to-date version of Portecle exists by querying
     * a properties file on the internet.
     */
    /*
     private void checkForUpdate()
     {
     // Get the version number of this Portecle
     String sCurrentVersion = m_res.getString("FPortecle.Version");

     HttpURLConnection urlConn = null;
     ObjectInputStream ois = null;

     try
     {
     // Get the version number of the latest Portecle from the
     // Internet - present in a serialised Version object on the
     // Portecle web site

     // Build and connect to the relevant URL
     URL latestVersionUrl = new URL(
     m_res.getString("FPortecle.LatestVersionAddress"));
     urlConn = (HttpURLConnection) latestVersionUrl.openConnection();

     int iResponseCode = urlConn.getResponseCode();
     if (iResponseCode != HttpURLConnection.HTTP_OK)
     {
     // Bad response code from server
     JOptionPane.showMessageDialog(
     this,
     MessageFormat.format(
     m_res.getString("FPortecle.Non200Response.message"),
     new Object[]{""+iResponseCode, latestVersionUrl}),
     m_res.getString("FPortecle.Title"),
     JOptionPane.ERROR_MESSAGE
     );
     return;
     }

     // Attempt to read serialized Version into an object
     ois = new ObjectInputStream(urlConn.getInputStream());
     Version latestVersion = (Version) ois.readObject();

     // Construct current version into a Version object for comparison
     Version currentVersion = new Version(sCurrentVersion);

     // Make comparison
     int iCmp = currentVersion.compareTo(latestVersion);

     if (iCmp >= 0)
     {
     // Latest version same (or less!) then current version -
     // tell user they are up-to-date
     JOptionPane.showMessageDialog(
     this,
     MessageFormat.format(
     m_res.getString("FPortecle.HaveLatestVersion.message"),
     new Object[]{currentVersion}),
     m_res.getString("FPortecle.Title"),
     JOptionPane.INFORMATION_MESSAGE);
     }
     else
     {
     int iSelected = JOptionPane.showConfirmDialog(
     this,
     MessageFormat.format(
     m_res.getString(
     "FPortecle.NewerVersionAvailable.message"),
     new Object[]{latestVersion,
     m_res.getString(
     "FPortecle.DownloadsAddress")}),
     m_res.getString("FPortecle.Title"),
     JOptionPane.YES_NO_OPTION);
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
     try { ois.close(); } catch (IOException ex) {}
     }
     }
     }
     */

    /**
     * Display the Portecle downloads web page.
     */
    /*
     private void visitDownloads()
     {
     String sDownloadsAddress =
     m_res.getString("FPortecle.DownloadsAddress");

     try
     {
     BrowserLauncher.openURL(sDownloadsAddress);
     }
     catch (IOException ex)
     {
     // Could not launch web browser - tell the user the address
     JOptionPane.showMessageDialog(
     this,
     MessageFormat.format(
     m_res.getString("FPortecle.NoLaunchBrowser.message"),
     new String[]{sDownloadsAddress}),
     m_res.getString("FPortecle.Title"),
     JOptionPane.INFORMATION_MESSAGE);
     }
     }
     */

    /**
     * Display donation web page.
     */
    private void makeDonation()
    {
        String sDonateAddress = m_res.getString("FPortecle.DonateAddress");
        try {
            BrowserLauncher.openURL(sDonateAddress);
        }
        catch (IOException ex) {
            // Could not launch web browser - tell the user the address
            JOptionPane.showMessageDialog(this, MessageFormat.format(
                m_res.getString("FPortecle.NoLaunchBrowser.message"),
                new String[] { sDonateAddress }),
                m_res.getString("FPortecle.Title"),
                JOptionPane.INFORMATION_MESSAGE);
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
        try {
            DJarInfo dJarInfo = new DJarInfo(this, true);
            dJarInfo.setLocationRelativeTo(this);
            dJarInfo.setVisible(true);
        }
        catch (IOException ex) {
            displayException(ex);
        }
    }

    /**
     * Display the options dialog and store the user's choices.
     */
    private void showOptions()
    {
        DOptions dOptions = new DOptions(this, true, m_bUseCaCerts,
            m_fCaCertsFile);
        dOptions.setLocationRelativeTo(this);
        dOptions.setVisible(true);

        // Store/apply the chosen options:

        // CA certs file
        File fTmp = dOptions.getCaCertsFile();

        if (!fTmp.equals(m_fCaCertsFile)) {
            // CA certs file changed - any stored CA certs keystore is
            // now invalid
            m_caCertsKeyStore = null;
        }

        m_fCaCertsFile = fTmp;

        // Use CA certs?
        m_bUseCaCerts = dOptions.getUseCaCerts();

        // Look & feel
        UIManager.LookAndFeelInfo lookFeelInfo = dOptions.getLookFeelInfo();

        // Look & feel decoration
        boolean bLookFeelDecoration = dOptions.getLookFeelDecoration();

        // Look & feel/decoration changed?
        /* Note: UIManager.LookAndFeelInfo.getName() and LookAndFeel.getName()
         can be different for the same L&F (one example is the GTK+ one
         in J2SE 5 RC2 (Linux), where the former is "GTK+" and the latter is
         "GTK look and feel"). Therefore, compare the class names instead. */
        if (lookFeelInfo != null) {
            if (!lookFeelInfo.getClassName().equals(
                UIManager.getLookAndFeel().getClass().getName())
                || bLookFeelDecoration != JFrame.isDefaultLookAndFeelDecorated())
            {
                // TODO: offer a choice to keep working without making the
                // change

                // Yes - save selections to be picked up by app preferences,
                m_lookFeelOptions = lookFeelInfo;
                m_bLookFeelDecorationOptions = Boolean.valueOf(bLookFeelDecoration);

                if (EXPERIMENTAL) {
                    saveAppPrefs();
                    setVisible(false);
                    MetalLookAndFeel.setCurrentTheme(METAL_THEME);
                    /* Can't get these to apply on the fly ???
                     JFrame.setDefaultLookAndFeelDecorated(bLookFeelDecoration);
                     JDialog.setDefaultLookAndFeelDecorated(
                     bLookFeelDecoration);
                     */
                    try {
                        UIManager.setLookAndFeel(lookFeelInfo.getClassName());
                        SwingUtilities.updateComponentTreeUI(getRootPane());
                        pack();
                    }
                    catch (Exception e) {
                        displayException(e);
                    }
                    finally {
                        setVisible(true);
                    }
                }
                else {
                    // Save and exit application
                    JOptionPane.showMessageDialog(this,
                        m_res.getString("FPortecle.LookFeelChanged.message"),
                        m_res.getString("FPortecle.LookFeelChanged.Title"),
                        JOptionPane.INFORMATION_MESSAGE);
                    exitApplication();
                }
            }
        }
    }

    /**
     * Convert the loaded keystore's type to that supplied.
     *
     * @param keyStoreType New keystore type
     * @return True if the keystore's type was changed, false otherwise
     */
    private boolean changeKeyStoreType(KeyStoreType keyStoreType)
    {
        assert m_keyStoreWrap.getKeyStore() != null;
        // Cannot change type to current type
        assert !m_keyStoreWrap.getKeyStore().getType().equals(
            keyStoreType.toString());

        try {
            // Get current keystore and type
            KeyStore currentKeyStore = m_keyStoreWrap.getKeyStore();
            String sCurrentType = m_keyStoreWrap.getKeyStore().getType();

            // Create empty keystore of new type
            KeyStore newKeyStore = KeyStoreUtil.createKeyStore(keyStoreType);

            // Flag used to tell if we have warned the user about default key
            // pair entry passwords for keystores changed to PKCS #12
            boolean bWarnPkcs12Password = false;

            // Flag used to tell if we have warned the user about key entries
            // not being carried over by the change
            boolean bWarnNoChangeKey = false;

            // Flag used to tell if we have warned the user about alias case
            // sensitivity issues involved with the conversion
            boolean bWarnCaseSensitivity = false;

            // For every entry in the current keystore transfer it to the new
            // one - get key/key pair entry passwords from the wrapper and if
            // not present there from the user
            for (Enumeration aliases = currentKeyStore.aliases(); aliases.hasMoreElements();)
            {
                // Entry alias
                String sAlias = (String) aliases.nextElement();

                // Trusted certificate entry
                if (currentKeyStore.isCertificateEntry(sAlias)) {
                    // Get trusted certificate and place it in the new keystore
                    Certificate trustedCertificate = currentKeyStore.getCertificate(sAlias);

                    // Check and ask about case insensitivity issues
                    if (newKeyStore.containsAlias(sAlias)
                        && !bWarnCaseSensitivity)
                    {
                        bWarnCaseSensitivity = true;
                        int iSelected = JOptionPane.showConfirmDialog(
                            this,
                            m_res.getString("FPortecle.WarnCaseSensitivity.message"),
                            m_res.getString("FPortecle.ChangeKeyStoreType.Title"),
                            JOptionPane.YES_NO_OPTION);
                        if (iSelected != JOptionPane.YES_OPTION) {
                            return false;
                        }
                    }

                    newKeyStore.setCertificateEntry(sAlias, trustedCertificate);
                }
                // Key or Key pair entry
                else if (currentKeyStore.isKeyEntry(sAlias)) {
                    // Get certificate chain - will be null if entry is key
                    Certificate[] certificateChain = currentKeyStore.getCertificateChain(sAlias);

                    if (certificateChain == null
                        || certificateChain.length == 0)
                    {
                        // Key entries are not transferred - warn the user
                        // if we have no done so already
                        if (!bWarnNoChangeKey) {
                            bWarnNoChangeKey = true;
                            int iSelected = JOptionPane.showConfirmDialog(
                                this,
                                m_res.getString("FPortecle.WarnNoChangeKey.message"),
                                m_res.getString("FPortecle.ChangeKeyStoreType.Title"),
                                JOptionPane.YES_NO_OPTION);
                            if (iSelected != JOptionPane.YES_OPTION) {
                                return false;
                            }
                        }

                        continue;
                    }

                    // Get the entry's password (we may already know it from
                    // the wrapper)
                    char[] cPassword = m_keyStoreWrap.getEntryPassword(sAlias);

                    if (cPassword == null) {
                        cPassword = PKCS12_DUMMY_PASSWORD;

                        // Password is only relevant if the current keystore
                        // type is not PKCS #12
                        if (!sCurrentType.equals(KeyStoreType.PKCS12.toString()))
                        {
                            String sTitle = MessageFormat.format(
                                m_res.getString("FPortecle.ChangeKeyStoreTypeKeyPairEntryPassword.Title"),
                                new String[] { sAlias });
                            DGetPassword dGetPassword = new DGetPassword(this,
                                sTitle, true);
                            dGetPassword.setLocationRelativeTo(this);
                            dGetPassword.setVisible(true);
                            cPassword = dGetPassword.getPassword();

                            if (cPassword == null) {
                                return false;
                            }
                        }
                    }

                    // Use password to get key pair
                    Key key = currentKeyStore.getKey(sAlias, cPassword);

                    // The current keystore type is PKCS #12 so entry password
                    // will be set to the PKCS #12 "dummy value" password
                    if (sCurrentType.equals(KeyStoreType.PKCS12.toString())) {
                        // Warn the user about this
                        if (!bWarnPkcs12Password) {
                            bWarnPkcs12Password = true;
                            JOptionPane.showMessageDialog(
                                this,
                                MessageFormat.format(
                                    m_res.getString("FPortecle.ChangeFromPkcs12Password.message"),
                                    new String[] { new String(
                                        PKCS12_DUMMY_PASSWORD) }),
                                m_res.getString("FPortecle.ChangeKeyStoreType.Title"),
                                JOptionPane.INFORMATION_MESSAGE);
                        }
                    }
                    // The new keystore type is PKCS #12 so use
                    // "dummy value" password for entry
                    else if (keyStoreType == KeyStoreType.PKCS12) {
                        cPassword = PKCS12_DUMMY_PASSWORD;
                    }

                    // Check and ask about case insensitivity issues
                    if (newKeyStore.containsAlias(sAlias)
                        && !bWarnCaseSensitivity)
                    {
                        bWarnCaseSensitivity = true;
                        int iSelected = JOptionPane.showConfirmDialog(
                            this,
                            m_res.getString("FPortecle.WarnCaseSensitivity.message"),
                            m_res.getString("FPortecle.ChangeKeyStoreType.Title"),
                            JOptionPane.YES_NO_OPTION);
                        if (iSelected != JOptionPane.YES_OPTION) {
                            return false;
                        }
                    }

                    // Put key and (possibly null) certificate chain in
                    // new keystore
                    newKeyStore.setKeyEntry(sAlias, key, cPassword,
                        certificateChain);

                    // Update wrapper with password
                    m_keyStoreWrap.setEntryPassword(sAlias, cPassword);
                }
            }

            // Successful change of type - put new keystore into wrapper
            KeyStoreType oldType = m_keyStoreWrap.getKeyStoreType(); 
            m_keyStoreWrap.setKeyStore(newKeyStore);
            File oldFile = m_keyStoreWrap.getKeyStoreFile(); 
            if (oldFile != null) {
                String[] oldExts = oldType.getFilenameExtensions();
                String[] newExts = keyStoreType.getFilenameExtensions();
                if (oldExts != null && newExts != null) {
                    String newExt = newExts[0];
                    for (int i = 0, len = oldExts.length; i < len; i++) {
                        String path = oldFile.getPath();
                        if (path.endsWith("." + oldExts[i])) {
                            m_keyStoreWrap.setKeyStoreFile(new File(
                                path.substring(0, path.length() - oldExts[i].length()) + newExt));
                        }
                    }
                    if (oldFile.equals(m_keyStoreWrap.getKeyStoreFile())) {
                        m_keyStoreWrap.setKeyStoreFile(null);
                    }
                }
                else {
                    m_keyStoreWrap.setKeyStoreFile(null);
                }
            }
            m_keyStoreWrap.setChanged(true);

            // Update the frame's components and title
            updateControls();
            updateTitle();

            // Display success message
            JOptionPane.showMessageDialog(
                this,
                m_res.getString("FPortecle.ChangeKeyStoreTypeSuccessful.message"),
                m_res.getString("FPortecle.ChangeKeyStoreType.Title"),
                JOptionPane.INFORMATION_MESSAGE);
            return true;
        }
        catch (Exception ex) {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user set the keystore's password.
     *
     * @return True if the password was set, false otherwise
     */
    private boolean setKeyStorePassword()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        char[] cPassword = getNewKeyStorePassword();

        // User cancelled
        if (cPassword == null) {
            return false;
        }

        // Update the keystore wrapper
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
        // Not relevant for a PKCS #12 keystore
        assert !m_keyStoreWrap.getKeyStore().getType().equals(
            KeyStoreType.PKCS12.toString());

        // What entry has been selected?
        int iRow = m_jtKeyStore.getSelectedRow();

        if (iRow == -1) {
            return false;
        }

        // Not valid for a certificate entry, nor a key-only one - we do a
        // remove-store operation but the KeyStore API won't allow us to
        // store a PrivateKey without associated certificate chain.
        // TODO: Maybe it'd work for other Key types? Need testing material.
        Object currEntry = m_jtKeyStore.getValueAt(iRow, 0);
        if (currEntry.equals(KeyStoreTableModel.KEY_ENTRY) ||
            currEntry.equals(KeyStoreTableModel.TRUST_CERT_ENTRY))
        {
            return false;
        }

        // Get entry alias
        String sAlias = (String) m_jtKeyStore.getValueAt(iRow, 1);

        // Do we already know the current password for the entry?
        char[] cOldPassword = m_keyStoreWrap.getEntryPassword(sAlias);

        // Display the change password dialog supplying the current password
        // to it if it was available
        DChangePassword dChangePassword = new DChangePassword(this, true,
            m_res.getString("FPortecle.SetKeyPairPassword.Title"),
            cOldPassword);
        dChangePassword.setLocationRelativeTo(this);
        dChangePassword.setVisible(true);

        // Get the password settings the user made in the dialog
        if (cOldPassword == null) {
            cOldPassword = dChangePassword.getOldPassword();
        }
        char[] cNewPassword = dChangePassword.getNewPassword();

        // Dialog was cancelled
        if (cOldPassword == null || cNewPassword == null) {
            return false;
        }

        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        try {
            // Change the password by recreating the entry
            Certificate[] cert = keyStore.getCertificateChain(sAlias);
            Key key = keyStore.getKey(sAlias, cOldPassword);
            keyStore.deleteEntry(sAlias);
            keyStore.setKeyEntry(sAlias, key, cNewPassword, cert);

            // Update the keystore wrapper
            m_keyStoreWrap.setEntryPassword(sAlias, cNewPassword);
            m_keyStoreWrap.setChanged(true);
        }
        catch (GeneralSecurityException ex) {
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

        if (iRow == -1) {
            return false;
        }

        // TODO: implement this for key-only entries
        if (m_jtKeyStore.getValueAt(iRow, 0).equals(
            KeyStoreTableModel.KEY_ENTRY))
        {
            return false;
        }

        // Get the entry
        String sAlias = (String) m_jtKeyStore.getValueAt(iRow, 1);

        try {
            // Display the Generate Key Pair dialog to get the key pair
            // generation parameters from the user
            DExport dExport = new DExport(this, true, m_keyStoreWrap, sAlias);
            dExport.setLocationRelativeTo(this);
            dExport.setVisible(true);

            if (!dExport.exportSelected()) {
                return false; // User cancelled the dialog
            }

            // Do export
            boolean bSuccess = false;

            // Export head certificate only
            if (dExport.exportHead()) {
                // Export PEM encoded format
                if (dExport.exportPem()) {
                    bSuccess = exportHeadCertOnlyPem(sAlias);
                }
                // Export DER encoded format
                else if (dExport.exportDer()) {
                    bSuccess = exportHeadCertOnlyDER(sAlias);
                }
                // Export PkiPath format
                else if (dExport.exportPkiPath()) {
                    bSuccess = exportHeadCertOnlyPkiPath(sAlias);
                }
                // Export PKCS #7 format
                else // if (dExport.exportPkcs7())
                {
                    bSuccess = exportHeadCertOnlyPkcs7(sAlias);
                }
            }
            // Complete cert path (PKCS #7 or PkiPath)
            else if (dExport.exportChain()) {
                if (dExport.exportPkiPath()) {
                    bSuccess = exportAllCertsPkiPath(sAlias);
                }
                else // if (dExport.exportPkcs7())
                {
                    bSuccess = exportAllCertsPkcs7(sAlias);
                }
            }
            // Complete cert path and private key (PKCS #12)
            else {
                if (dExport.exportPem()) {
                    bSuccess = exportPrivKeyCertChainPEM(sAlias);
                }
                else // if (dExport.exportPkcs12())
                {
                    bSuccess = exportPrivKeyCertChainPKCS12(sAlias);
                }
            }

            if (bSuccess) {
                // Display success message
                JOptionPane.showMessageDialog(this,
                    m_res.getString("FPortecle.ExportSuccessful.message"),
                    m_res.getString("FPortecle.Export.Title"),
                    JOptionPane.INFORMATION_MESSAGE);
            }
        }
        catch (Exception ex) {
            displayException(ex);
            return false;
        }

        return true;
    }

    /**
     * Export the head certificate of the keystore entry in a PEM encoding.
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportHeadCertOnlyPem(String sEntryAlias)
    {
        X509Certificate cert = null;
        try {
            cert = getHeadCert(sEntryAlias);
        }
        catch (CryptoException ex) {
            displayException(ex);
            return false;
        }

        String basename = X509CertUtil.getCertificateAlias(cert);
        if (basename.length() == 0) {
            basename = sEntryAlias;
        }

        // Let the user choose the export cert file
        File fExportFile = chooseExportCertFile(basename);
        if (fExportFile == null) {
            return false;
        }

        if (!confirmOverwrite(fExportFile, getTitle())) {
            return false;
        }

        PEMWriter pw = null;
        try {
            pw = new PEMWriter(new FileWriter(fExportFile));
            pw.writeObject(cert);
            m_lastDir.updateLastDir(fExportFile);
            return true;
        }
        catch (FileNotFoundException ex) {
            String sMessage = MessageFormat.format(
                m_res.getString("FPortecle.NoWriteFile.message"),
                new String[] { fExportFile.getName() });
            JOptionPane.showMessageDialog(this, sMessage, getTitle(),
                JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (IOException ex) {
            displayException(ex);
            return false;
        }
        finally {
            if (pw != null) {
                try {
                    pw.close();
                }
                catch (IOException ex) {
                    displayException(ex);
                }
            }
        }
    }

    /**
     * Export the head certificate of the keystore entry in a DER encoding.
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportHeadCertOnlyDER(String sEntryAlias)
    {
        X509Certificate cert = null;
        try {
            // Get the head certificate
            cert = getHeadCert(sEntryAlias);
        }
        catch (CryptoException ex) {
            displayException(ex);
            return false;
        }

        String basename = X509CertUtil.getCertificateAlias(cert);
        if (basename.length() == 0) {
            basename = sEntryAlias;
        }

        // Let the user choose the export cert file
        File fExportFile = chooseExportCertFile(basename);
        if (fExportFile == null) {
            return false;
        }

        if (!confirmOverwrite(fExportFile, getTitle())) {
            return false;
        }

        FileOutputStream fos = null;
        try {
            // Do the export
            byte[] bEncoded = X509CertUtil.getCertEncodedDer(cert);
            fos = new FileOutputStream(fExportFile);
            fos.write(bEncoded);

            m_lastDir.updateLastDir(fExportFile);

            return true;
        }
        catch (FileNotFoundException ex) {
            String sMessage = MessageFormat.format(
                m_res.getString("FPortecle.NoWriteFile.message"),
                new String[] { fExportFile.getName() });
            JOptionPane.showMessageDialog(this, sMessage, getTitle(),
                JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (IOException ex) {
            displayException(ex);
            return false;
        }
        catch (CryptoException ex) {
            displayException(ex);
            return false;
        }
        finally {
            if (fos != null) {
                try {
                    fos.close();
                }
                catch (IOException ex) {
                    displayException(ex);
                }
            }
        }
    }

    /**
     * Export the head certificate of the keystore entry to a PKCS #7 file.
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportHeadCertOnlyPkcs7(String sEntryAlias)
    {
        X509Certificate cert = null;
        try {
            // Get the head certificate
            cert = getHeadCert(sEntryAlias);
        }
        catch (CryptoException ex) {
            displayException(ex);
            return false;
        }

        String basename = X509CertUtil.getCertificateAlias(cert);
        if (basename.length() == 0) {
            basename = sEntryAlias;
        }

        // Let the user choose the export PKCS #7 file
        File fExportFile = chooseExportPKCS7File(basename);
        if (fExportFile == null) {
            return false;
        }

        if (!confirmOverwrite(fExportFile, getTitle())) {
            return false;
        }

        FileOutputStream fos = null;
        try {
            // Do the export
            byte[] bEncoded = X509CertUtil.getCertEncodedPkcs7(cert);
            fos = new FileOutputStream(fExportFile);
            fos.write(bEncoded);

            m_lastDir.updateLastDir(fExportFile);

            return true;
        }
        catch (FileNotFoundException ex) {
            String sMessage = MessageFormat.format(
                m_res.getString("FPortecle.NoWriteFile.message"),
                new String[] { fExportFile.getName() });
            JOptionPane.showMessageDialog(this, sMessage, getTitle(),
                JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (IOException ex) {
            displayException(ex);
            return false;
        }
        catch (CryptoException ex) {
            displayException(ex);
            return false;
        }
        finally {
            if (fos != null) {
                try {
                    fos.close();
                }
                catch (IOException e) {
                    displayException(e);
                }
            }
        }
    }

    /**
     * Export the head certificate of the keystore entry to a PkiPath file.
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportHeadCertOnlyPkiPath(String sEntryAlias)
    {
        X509Certificate cert = null;
        try {
            // Get the head certificate
            cert = getHeadCert(sEntryAlias);
        }
        catch (CryptoException ex) {
            displayException(ex);
            return false;
        }

        String basename = X509CertUtil.getCertificateAlias(cert);
        if (basename.length() == 0) {
            basename = sEntryAlias;
        }

        // Let the user choose the export PkiPath file
        File fExportFile = chooseExportPkiPathFile(basename);
        if (fExportFile == null) {
            return false;
        }

        if (!confirmOverwrite(fExportFile, getTitle())) {
            return false;
        }

        FileOutputStream fos = null;
        try {
            // Do the export
            byte[] bEncoded = X509CertUtil.getCertEncodedPkiPath(cert);
            fos = new FileOutputStream(fExportFile);
            fos.write(bEncoded);

            m_lastDir.updateLastDir(fExportFile);

            return true;
        }
        catch (FileNotFoundException ex) {
            String sMessage = MessageFormat.format(
                m_res.getString("FPortecle.NoWriteFile.message"),
                new String[] { fExportFile.getName() });
            JOptionPane.showMessageDialog(this, sMessage, getTitle(),
                JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (IOException ex) {
            displayException(ex);
            return false;
        }
        catch (CryptoException ex) {
            displayException(ex);
            return false;
        }
        finally {
            if (fos != null) {
                try {
                    fos.close();
                }
                catch (IOException e) {
                    displayException(e);
                }
            }
        }
    }

    /**
     * Export all of the certificates of the keystore entry to a PKCS #7 file.
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportAllCertsPkcs7(String sEntryAlias)
    {
        // Get the certificates
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();
        X509Certificate[] certChain = null;
        try {
            certChain = X509CertUtil.convertCertificates(keyStore.getCertificateChain(sEntryAlias));
        }
        catch (KeyStoreException ex) {
            displayException(ex);
            return false;
        }
        catch (CryptoException ex) {
            displayException(ex);
            return false;
        }

        String basename = null;
        if (certChain.length > 0) {
            basename = X509CertUtil.getCertificateAlias(certChain[0]);
        }
        if (basename == null || basename.length() == 0) {
            basename = sEntryAlias;
        }

        // Let the user choose the export PKCS #7 file
        File fExportFile = chooseExportPKCS7File(basename);
        if (fExportFile == null) {
            return false;
        }

        if (!confirmOverwrite(fExportFile, getTitle())) {
            return false;
        }

        FileOutputStream fos = null;
        try {
            // Do the export
            byte[] bEncoded = X509CertUtil.getCertsEncodedPkcs7(certChain);
            fos = new FileOutputStream(fExportFile);
            fos.write(bEncoded);

            m_lastDir.updateLastDir(fExportFile);

            return true;
        }
        catch (FileNotFoundException ex) {
            String sMessage = MessageFormat.format(
                m_res.getString("FPortecle.NoWriteFile.message"),
                new String[] { fExportFile.getName() });
            JOptionPane.showMessageDialog(this, sMessage, getTitle(),
                JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (IOException ex) {
            displayException(ex);
            return false;
        }
        catch (CryptoException ex) {
            displayException(ex);
            return false;
        }
        finally {
            if (fos != null) {
                try {
                    fos.close();
                }
                catch (IOException e) {
                    displayException(e);
                }
            }
        }
    }

    /**
     * Export all of the certificates of the keystore entry to a PkiPath file.
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportAllCertsPkiPath(String sEntryAlias)
    {
        // Get the certificates
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();
        X509Certificate[] certChain = null;
        try {
            certChain = X509CertUtil.convertCertificates(keyStore.getCertificateChain(sEntryAlias));
        }
        catch (KeyStoreException ex) {
            displayException(ex);
            return false;
        }
        catch (CryptoException ex) {
            displayException(ex);
            return false;
        }

        String basename = null;
        if (certChain.length > 0) {
            basename = X509CertUtil.getCertificateAlias(certChain[0]);
        }
        if (basename == null || basename.length() == 0) {
            basename = sEntryAlias;
        }

        // Let the user choose the export PkiPath file
        File fExportFile = chooseExportPkiPathFile(basename);
        if (fExportFile == null) {
            return false;
        }

        if (!confirmOverwrite(fExportFile, getTitle())) {
            return false;
        }

        FileOutputStream fos = null;
        try {
            // Do the export
            byte[] bEncoded = X509CertUtil.getCertsEncodedPkiPath(certChain);
            fos = new FileOutputStream(fExportFile);
            fos.write(bEncoded);

            m_lastDir.updateLastDir(fExportFile);

            return true;
        }
        catch (FileNotFoundException ex) {
            String sMessage = MessageFormat.format(
                m_res.getString("FPortecle.NoWriteFile.message"),
                new String[] { fExportFile.getName() });
            JOptionPane.showMessageDialog(this, sMessage, getTitle(),
                JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (IOException ex) {
            displayException(ex);
            return false;
        }
        catch (CryptoException ex) {
            displayException(ex);
            return false;
        }
        finally {
            if (fos != null) {
                try {
                    fos.close();
                }
                catch (IOException e) {
                    displayException(e);
                }
            }
        }
    }

    /**
     * Get the keystore entry's head certificate.
     *
     * @param sEntryAlias Entry alias
     * @return The keystore entry's head certificate
     * @throws CryptoException Problem getting head certificate
     */
    private X509Certificate getHeadCert(String sEntryAlias)
        throws CryptoException
    {
        try {
            // Get keystore
            KeyStore keyStore = m_keyStoreWrap.getKeyStore();

            // Get the entry's head certificate
            X509Certificate cert;
            if (keyStore.isKeyEntry(sEntryAlias)) {
                cert = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(keyStore.getCertificateChain(sEntryAlias)))[0];
            }
            else {
                cert = X509CertUtil.convertCertificate(keyStore.getCertificate(sEntryAlias));
            }

            return cert;
        }
        catch (KeyStoreException ex) {
            String sMessage = MessageFormat.format(
                m_res.getString("FPortecle.NoAccessEntry.message"),
                new String[] { sEntryAlias });
            throw new CryptoException(sMessage, ex);
        }
    }

    /**
     * Export the private key and certificates of the keystore entry to
     * a PEM encoded "OpenSSL" format bundle.
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportPrivKeyCertChainPEM(String sEntryAlias)
    {
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        // Get the entry's password (we may already know it from the wrapper)
        char[] cPassword = m_keyStoreWrap.getEntryPassword(sEntryAlias);

        if (cPassword == null) {
            cPassword = PKCS12_DUMMY_PASSWORD;

            // Password is only relevant if the keystore is not PKCS #12
            if (!keyStore.getType().equals(KeyStoreType.PKCS12.toString())) {
                DGetPassword dGetPassword = new DGetPassword(this,
                    m_res.getString("FPortecle.KeyEntryPassword.Title"), true);
                dGetPassword.setLocationRelativeTo(this);
                dGetPassword.setVisible(true);
                cPassword = dGetPassword.getPassword();

                if (cPassword == null) {
                    return false;
                }
            }
        }

        File fExportFile = null;
        PEMWriter pw = null;

        try {
            // Get the private key and certificate chain from the entry
            Key privKey = keyStore.getKey(sEntryAlias, cPassword);
            Certificate[] certs = keyStore.getCertificateChain(sEntryAlias);

            String basename = null;
            if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                basename = X509CertUtil.getCertificateAlias((X509Certificate) certs[0]);
            }
            if (basename == null || basename.length() == 0) {
                basename = sEntryAlias;
            }

            // Let the user choose the PEM export file
            fExportFile = chooseExportPEMFile(basename);
            if (fExportFile == null) {
                return false;
            }

            if (!confirmOverwrite(fExportFile, getTitle())) {
                return false;
            }

            // Do the export
            pw = new PEMWriter(new FileWriter(fExportFile));
            // TODO: private key encryption?
            pw.writeObject(privKey);
            for (int i = 0, len = certs.length; i < len; i++) {
                pw.writeObject(certs[i]);
            }
            pw.flush();

            m_lastDir.updateLastDir(fExportFile);

            return true;
        }
        catch (FileNotFoundException ex) {
            String sMessage = MessageFormat.format(
                m_res.getString("FPortecle.NoWriteFile.message"),
                new String[] { fExportFile.getName() });
            JOptionPane.showMessageDialog(this, sMessage, getTitle(),
                JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (IOException ex) {
            displayException(ex);
            return false;
        }
        catch (GeneralSecurityException ex) {
            displayException(ex);
            return false;
        }
        finally {
            if (pw != null) {
                try {
                    pw.close();
                }
                catch (IOException ex) {
                    displayException(ex);
                }
            }
        }
    }

    /**
     * Export the private key and certificates of the keystore entry to
     * a PKCS #12 keystore file.
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportPrivKeyCertChainPKCS12(String sEntryAlias)
    {
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        // Get the entry's password (we may already know it from the wrapper)
        char[] cPassword = m_keyStoreWrap.getEntryPassword(sEntryAlias);

        if (cPassword == null) {
            cPassword = PKCS12_DUMMY_PASSWORD;

            // Password is only relevant if the keystore is not PKCS #12
            if (!keyStore.getType().equals(KeyStoreType.PKCS12.toString())) {
                DGetPassword dGetPassword = new DGetPassword(this,
                    m_res.getString("FPortecle.KeyEntryPassword.Title"), true);
                dGetPassword.setLocationRelativeTo(this);
                dGetPassword.setVisible(true);
                cPassword = dGetPassword.getPassword();

                if (cPassword == null) {
                    return false;
                }
            }
        }

        File fExportFile = null;

        try {
            // Get the private key and certificate chain from the entry
            Key privKey = keyStore.getKey(sEntryAlias, cPassword);
            Certificate[] certs = keyStore.getCertificateChain(sEntryAlias);

            // Update the keystore wrapper
            m_keyStoreWrap.setEntryPassword(sEntryAlias, cPassword);

            // Create a new PKCS #12 keystore
            KeyStore pkcs12 = KeyStoreUtil.createKeyStore(KeyStoreType.PKCS12);

            // Place the private key and certificate chain into the PKCS #12
            // keystore under the same alias as it has in the loaded keystore
            pkcs12.setKeyEntry(sEntryAlias, privKey, new char[0], certs);

            // Get a new password for the PKCS #12 keystore
            DGetNewPassword dGetNewPassword = new DGetNewPassword(this,
                m_res.getString("FPortecle.Pkcs12Password.Title"), true);
            dGetNewPassword.setLocationRelativeTo(this);
            dGetNewPassword.setVisible(true);

            char[] cPKCS12Password = dGetNewPassword.getPassword();

            if (cPKCS12Password == null) {
                return false;
            }

            String basename = null;
            if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                basename = X509CertUtil.getCertificateAlias((X509Certificate) certs[0]);
            }
            if (basename == null || basename.length() == 0) {
                basename = sEntryAlias;
            }

            // Let the user choose the export PKCS #12 file
            fExportFile = chooseExportPKCS12File(basename);
            if (fExportFile == null) {
                return false;
            }

            if (!confirmOverwrite(fExportFile, getTitle())) {
                return false;
            }

            // Store the keystore to disk
            pkcs12 = KeyStoreUtil.saveKeyStore(pkcs12, fExportFile, cPKCS12Password);

            m_lastDir.updateLastDir(fExportFile);

            return true;
        }
        catch (FileNotFoundException ex) {
            String sMessage = MessageFormat.format(
                m_res.getString("FPortecle.NoWriteFile.message"),
                new String[] { fExportFile.getName() });
            JOptionPane.showMessageDialog(this, sMessage, getTitle(),
                JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (IOException ex) {
            displayException(ex);
            return false;
        }
        catch (GeneralSecurityException ex) {
            displayException(ex);
            return false;
        }
        catch (CryptoException ex) {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user choose a certificate file to export to.
     *
     * @param basename default filename (without extension)
     * @return The chosen file or null if none was chosen
     */
    private File chooseExportCertFile(String basename)
    {
        JFileChooser chooser = FileChooserFactory.getX509FileChooser(basename);

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FPortecle.ExportCertificate.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this,
            m_res.getString("FPortecle.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            File fExportFile = chooser.getSelectedFile();
            return fExportFile;
        }
        return null;
    }

    /**
     * Let the user choose a PKCS #7 file to export to.
     *
     * @param basename default filename (without extension)
     * @return The chosen file or null if none was chosen
     */
    private File chooseExportPKCS7File(String basename)
    {
        JFileChooser chooser = FileChooserFactory.getPkcs7FileChooser(basename);

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FPortecle.ExportCertificates.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this,
            m_res.getString("FPortecle.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            File fExportFile = chooser.getSelectedFile();
            return fExportFile;
        }
        return null;
    }

    /**
     * Let the user choose a PkiPath file to export to.
     *
     * @param basename default filename (without extension)
     * @return The chosen file or null if none was chosen
     */
    private File chooseExportPkiPathFile(String basename)
    {
        JFileChooser chooser = FileChooserFactory.getPkiPathFileChooser(basename);

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FPortecle.ExportCertificates.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this,
            m_res.getString("FPortecle.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            File fExportFile = chooser.getSelectedFile();
            return fExportFile;
        }
        return null;
    }

    /**
     * Let the user choose a PKCS #12 file to export to.
     *
     * @param basename default filename (without extension)
     * @return The chosen file or null if none was chosen
     */
    private File chooseExportPKCS12File(String basename)
    {
        JFileChooser chooser = FileChooserFactory.getPkcs12FileChooser(basename);

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FPortecle.ExportKeyCertificates.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this,
            m_res.getString("FPortecle.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            File fExportFile = chooser.getSelectedFile();
            return fExportFile;
        }
        return null;
    }

    /**
     * Let the user choose a PEM file to export to.
     *
     * @param basename default filename (without extension)
     * @return The chosen file or null if none was chosen
     */
    private File chooseExportPEMFile(String basename)
    {
        JFileChooser chooser = FileChooserFactory.getPEMFileChooser(basename);

        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }

        chooser.setDialogTitle(m_res.getString("FPortecle.ExportKeyCertificates.Title"));
        chooser.setMultiSelectionEnabled(false);

        int iRtnValue = chooser.showDialog(this,
            m_res.getString("FPortecle.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
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

        if (iRow == -1) {
            return false;
        }

        // Not valid for a key-only or a trusted certificate entry
        Object currEntry = m_jtKeyStore.getValueAt(iRow, 0);
        if (currEntry.equals(KeyStoreTableModel.KEY_ENTRY) ||
            currEntry.equals(KeyStoreTableModel.TRUST_CERT_ENTRY))
        {
            return false;
        }

        String sAlias = (String) m_jtKeyStore.getValueAt(iRow, 1);
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        File fCsrFile = null;
        PEMWriter pw = null;

        try {
            // Get the entry's password (we may already know it from the
            // wrapper)
            char[] cPassword = m_keyStoreWrap.getEntryPassword(sAlias);

            if (cPassword == null) {
                cPassword = PKCS12_DUMMY_PASSWORD;

                // Password is only relevant if the keystore is not PKCS #12
                if (!keyStore.getType().equals(KeyStoreType.PKCS12.toString()))
                {
                    DGetPassword dGetPassword = new DGetPassword(this,
                        m_res.getString("FPortecle.KeyEntryPassword.Title"),
                        true);
                    dGetPassword.setLocationRelativeTo(this);
                    dGetPassword.setVisible(true);
                    cPassword = dGetPassword.getPassword();

                    if (cPassword == null) {
                        return false;
                    }
                }
            }

            // Get the key pair entry's private key using the password
            PrivateKey privKey = (PrivateKey) keyStore.getKey(sAlias,
                cPassword);

            // Update the keystore wrapper
            m_keyStoreWrap.setEntryPassword(sAlias, cPassword);

            // Get the first certficate in the entry's certificate chain
            X509Certificate cert = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(keyStore.getCertificateChain(sAlias)))[0];

            // Let the user choose the file to write the CSR to
            fCsrFile = chooseGenerateCsrFile(X509CertUtil.getCertificateAlias(cert));
            if (fCsrFile == null) {
                return false;
            }

            if (!confirmOverwrite(fCsrFile,
                m_res.getString("FPortecle.GenerateCsr.Title")))
            {
                return false;
            }

            // Generate CSR and write it out to file
            pw = new PEMWriter(new FileWriter(fCsrFile));
            pw.writeObject(X509CertUtil.generatePKCS10CSR(cert, privKey));

            // Display success message
            JOptionPane.showMessageDialog(this,
                m_res.getString("FPortecle.CsrGenerationSuccessful.message"),
                m_res.getString("FPortecle.GenerateCsr.Title"),
                JOptionPane.INFORMATION_MESSAGE);

            m_lastDir.updateLastDir(fCsrFile);

            return true;
        }
        catch (FileNotFoundException ex) {
            JOptionPane.showMessageDialog(this, MessageFormat.format(
                m_res.getString("FPortecle.NoWriteFile.message"),
                new Object[] { fCsrFile }),
                m_res.getString("FPortecle.GenerateCsr.Title"),
                JOptionPane.WARNING_MESSAGE);
            return false;
        }
        catch (Exception ex) {
            displayException(ex);
            return false;
        }
        finally {
            if (pw != null) {
                try {
                    pw.close();
                }
                catch (IOException ex) {
                    displayException(ex);
                }
            }
        }
    }

    /**
     * Let the user clone the selected key entry.
     *
     * @return True if the clone is successful, false otherwise
     */
    private boolean cloneSelectedKeyEntry()
    {

        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // What entry has been selected?
        int iRow = m_jtKeyStore.getSelectedRow();

        if (iRow == -1) {
            return false;
        }

        Object currEntry = m_jtKeyStore.getValueAt(iRow, 0);
        // Not valid for a PrivateKey-only entry - the KeyStore API won't allow
        // us to store a PrivateKey without associated certificate chain.
        // TODO: Maybe it'd work for other Key types? Need testing material.
        if (!currEntry.equals(KeyStoreTableModel.KEY_PAIR_ENTRY)) {
            return false;
        }

        String sAlias = (String) m_jtKeyStore.getValueAt(iRow, 1);
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        try {
            // Get the entry's password (we may already know it from
            // the wrapper)
            char[] cPassword = m_keyStoreWrap.getEntryPassword(sAlias);

            if (cPassword == null) {
                cPassword = PKCS12_DUMMY_PASSWORD;

                // Password is only relevant if the keystore is not PKCS #12
                if (!keyStore.getType().equals(KeyStoreType.PKCS12.toString()))
                {
                    DGetPassword dGetPassword = new DGetPassword(this,
                        m_res.getString("FPortecle.KeyEntryPassword.Title"),
                        true);
                    dGetPassword.setLocationRelativeTo(this);
                    dGetPassword.setVisible(true);
                    cPassword = dGetPassword.getPassword();

                    if (cPassword == null) {
                        return false;
                    }
                }
            }

            // Get key and certificates from entry
            Key key = keyStore.getKey(sAlias, cPassword);
            Certificate[] certs = keyStore.getCertificateChain(sAlias);

            // Update the keystore wrapper
            m_keyStoreWrap.setEntryPassword(sAlias, cPassword);

            // Get the alias of the new entry
            // TODO: certs can be null
            X509Certificate[] x509Certs = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(certs));

            DGetAlias dGetAlias = new DGetAlias(this,
                m_res.getString("FPortecle.ClonedKeyPairEntryAlias.Title"),
                true,
                X509CertUtil.getCertificateAlias(x509Certs[0]).toLowerCase());
            dGetAlias.setLocationRelativeTo(this);
            dGetAlias.setVisible(true);
            String sNewAlias = dGetAlias.getAlias();

            if (sNewAlias == null) {
                return false;
            }

            // Check new alias differs from the present one
            if (sNewAlias.equalsIgnoreCase(sAlias)) {
                JOptionPane.showMessageDialog(this, MessageFormat.format(
                    m_res.getString("FPortecle.CloneAliasIdentical.message"),
                    new String[] { sAlias }),
                    m_res.getString("FPortecle.CloneKeyPair.Title"),
                    JOptionPane.ERROR_MESSAGE);
                return false;
            }

            // Alias to possibly delete before adding new one
            String sAliasToDelete = null;

            // Check entry does not already exist in the keystore
            if (keyStore.containsAlias(sNewAlias)) {
                String sMessage = MessageFormat.format(
                    m_res.getString("FPortecle.OverwriteAlias.message"),
                    new String[] { sNewAlias });

                int iSelected = JOptionPane.showConfirmDialog(
                    this,
                    sMessage,
                    m_res.getString("FPortecle.ClonedKeyPairEntryAlias.Title"),
                    JOptionPane.YES_NO_OPTION);
                if (iSelected != JOptionPane.YES_OPTION) {
                    return false;
                }
                // Otherwise carry on - delete old entry later
                sAliasToDelete = sNewAlias;
            }

            // Get a password for the new keystore entry (only relevant if
            // the keystore is not PKCS #12)
            char[] cNewPassword = PKCS12_DUMMY_PASSWORD;

            if (!keyStore.getType().equals(KeyStoreType.PKCS12.toString())) {
                DGetNewPassword dGetNewPassword = new DGetNewPassword(
                    this,
                    m_res.getString("FPortecle.ClonedKeyPairEntryPassword.Title"),
                    true);
                dGetNewPassword.setLocationRelativeTo(this);
                dGetNewPassword.setVisible(true);
                cNewPassword = dGetNewPassword.getPassword();

                if (cNewPassword == null) {
                    return false;
                }
            }

            // If needed, delete old entry first
            if (sAliasToDelete != null) {
                keyStore.deleteEntry(sAliasToDelete);
            }
            
            // Create new entry
            keyStore.setKeyEntry(sNewAlias, key, cNewPassword, certs);

            // Update the keystore wrapper
            m_keyStoreWrap.setEntryPassword(sNewAlias, cNewPassword);
            m_keyStoreWrap.setChanged(true);

            // ...and update the frame's components and title
            updateControls();
            updateTitle();

            // Display success message
            JOptionPane.showMessageDialog(this,
                m_res.getString("FPortecle.KeyPairCloningSuccessful.message"),
                m_res.getString("FPortecle.CloneKeyPair.Title"),
                JOptionPane.INFORMATION_MESSAGE);

            return true;
        }
        catch (Exception ex) {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user clone the selected certificate entry.
     *
     * @return True if the clone is successful, false otherwise
     */
    private boolean cloneSelectedCertificateEntry()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // What entry has been selected?
        int iRow = m_jtKeyStore.getSelectedRow();

        if (iRow == -1) {
            return false;
        }

        // Not valid for non-certificate entries
        Object currEntry = m_jtKeyStore.getValueAt(iRow, 0);
        if (!currEntry.equals(KeyStoreTableModel.TRUST_CERT_ENTRY)) {
            return false;
        }

        String sAlias = (String) m_jtKeyStore.getValueAt(iRow, 1);
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        try {

            // Get certificate from entry
            Certificate cert = keyStore.getCertificate(sAlias);

            // Get the alias of the new entry
            X509Certificate x509Cert = X509CertUtil.convertCertificate(cert);

            DGetAlias dGetAlias = new DGetAlias(this,
                m_res.getString("FPortecle.ClonedTrustCertEntryAlias.Title"),
                true,
                X509CertUtil.getCertificateAlias(x509Cert).toLowerCase());
            dGetAlias.setLocationRelativeTo(this);
            dGetAlias.setVisible(true);
            String sNewAlias = dGetAlias.getAlias();

            if (sNewAlias == null) {
                return false;
            }

            // Check new alias differs from the present one
            if (sNewAlias.equalsIgnoreCase(sAlias)) {
                JOptionPane.showMessageDialog(this, MessageFormat.format(
                    m_res.getString("FPortecle.CloneAliasIdentical.message"),
                    new String[] { sAlias }),
                    m_res.getString("FPortecle.CloneCertificate.Title"),
                    JOptionPane.ERROR_MESSAGE);
                return false;
            }

            // Check entry does not already exist in the keystore
            if (keyStore.containsAlias(sNewAlias)) {
                String sMessage = MessageFormat.format(
                    m_res.getString("FPortecle.OverwriteAlias.message"),
                    new String[] { sNewAlias });

                int iSelected = JOptionPane.showConfirmDialog(
                    this,
                    sMessage,
                    m_res.getString("FPortecle.ClonedTrustCertEntryAlias.Title"),
                    JOptionPane.YES_NO_OPTION);
                if (iSelected != JOptionPane.YES_OPTION) {
                    return false;
                }
                // Otherwise carry on - delete entry to be copied over
                keyStore.deleteEntry(sNewAlias);
            }

            // Create new entry
            keyStore.setCertificateEntry(sNewAlias, cert);

            // Update the keystore wrapper
            m_keyStoreWrap.setChanged(true);

            // ...and update the frame's components and title
            updateControls();
            updateTitle();

            // Display success message
            JOptionPane.showMessageDialog(this,
                m_res.getString("FPortecle.CertificateCloningSuccessful.message"),
                m_res.getString("FPortecle.CloneCertificate.Title"),
                JOptionPane.INFORMATION_MESSAGE);

            return true;
        }
        catch (Exception ex) {
            displayException(ex);
            return false;
        }
    }

    /**
     * Display a report on the currently loaded keystore.
     *
     * @return True if the keystore report was displayed successfully,
     * false otherwise
     */
    private boolean keyStoreReport()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        try {
            DKeyStoreReport dKeyStoreReport = new DKeyStoreReport(this, true,
                m_keyStoreWrap.getKeyStore());
            dKeyStoreReport.setLocationRelativeTo(this);
            dKeyStoreReport.setVisible(true);
            return true;
        }
        catch (Exception ex) {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user see the certificate details of the selected keystore entry.
     *
     * @return True if the certificate details were viewed suceesfully,
     * false otherwise
     */
    private boolean showSelectedEntry()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // What entry has been selected?
        int iRow = m_jtKeyStore.getSelectedRow();

        if (iRow == -1) {
            return false;
        }

        // TODO: implement this for key-only entries
        if (m_jtKeyStore.getValueAt(iRow, 0).equals(
            KeyStoreTableModel.KEY_ENTRY))
        {
            return false;
        }

        String sAlias = (String) m_jtKeyStore.getValueAt(iRow, 1);
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        try {
            // Get the entry's certificates
            X509Certificate[] certs;
            if (keyStore.isKeyEntry(sAlias)) {
                // If entry is a key pair
                certs = X509CertUtil.convertCertificates(keyStore.getCertificateChain(sAlias));
            }
            else {
                // If entry is a trusted certificate
                certs = new X509Certificate[1];
                certs[0] = X509CertUtil.convertCertificate(keyStore.getCertificate(sAlias));
            }

            // Supply the certificates to the view certificate dialog
            DViewCertificate dViewCertificate = new DViewCertificate(this,
                MessageFormat.format(
                    m_res.getString("FPortecle.CertDetailsEntry.Title"),
                    new String[] { sAlias }), true, certs);
            dViewCertificate.setLocationRelativeTo(this);
            dViewCertificate.setVisible(true);
            return true;
        }
        catch (Exception ex) {
            displayException(ex);
            return false;
        }
    }

    /**
     * Let the user delete the selected keystore entry.
     *
     * @return True if the deletion is successful, false otherwise
     */
    private boolean deleteSelectedEntry()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // What entry has been selected?
        int iRow = m_jtKeyStore.getSelectedRow();

        if (iRow == -1) {
            return false;
        }

        String sAlias = (String) m_jtKeyStore.getValueAt(iRow, 1);
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        try {
            // Delete the entry
            keyStore.deleteEntry(sAlias);

            // Update the keystore wrapper
            m_keyStoreWrap.removeEntryPassword(sAlias);
            m_keyStoreWrap.setChanged(true);
        }
        catch (KeyStoreException ex) {
            displayException(ex);
            return false;
        }

        // Update the frame's components and title
        updateControls();
        updateTitle();

        return true;
    }

    /**
     * Let the user rename the selected keystore entry.
     *
     * @return True if the rename is successful, false otherwise
     */
    private boolean renameSelectedEntry()
    {
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // What entry has been selected?
        int iRow = m_jtKeyStore.getSelectedRow();

        if (iRow == -1) {
            return false;
        }

        // Not valid for a key-only entry - we do a remove-store operation
        // but the KeyStore API won't allow us to store a PrivateKey without
        // associated certificate chain.
        // TODO: Maybe it'd work for other Key types? Need testing material.
        if (m_jtKeyStore.getValueAt(iRow, 0).equals(
            KeyStoreTableModel.KEY_ENTRY))
        {
            return false;
        }

        String sAlias = (String) m_jtKeyStore.getValueAt(iRow, 1);
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        try {
            // Get the new entry alias
            DGetAlias dGetAlias = new DGetAlias(this,
                m_res.getString("FPortecle.NewEntryAlias.Title"), true, sAlias);
            dGetAlias.setLocationRelativeTo(this);
            dGetAlias.setVisible(true);
            String sNewAlias = dGetAlias.getAlias();

            if (sNewAlias == null) {
                return false;
            }

            // Check new alias differs from the present one
            if (sNewAlias.equalsIgnoreCase(sAlias)) {
                JOptionPane.showMessageDialog(this, MessageFormat.format(
                    m_res.getString("FPortecle.RenameAliasIdentical.message"),
                    new String[] { sAlias }),
                    m_res.getString("FPortecle.RenameEntry.Title"),
                    JOptionPane.ERROR_MESSAGE);
                return false;
            }

            // Check entry does not already exist in the keystore
            if (keyStore.containsAlias(sNewAlias)) {
                String sMessage = MessageFormat.format(
                    m_res.getString("FPortecle.OverWriteEntry.message"),
                    new String[] { sNewAlias });

                int iSelected = JOptionPane.showConfirmDialog(this, sMessage,
                    m_res.getString("FPortecle.RenameEntry.Title"),
                    JOptionPane.YES_NO_OPTION);
                if (iSelected != JOptionPane.YES_OPTION) {
                    return false;
                }
            }

            // Create the new entry with the new name and copy the old
            // entry across

            // If the entry is a key pair...
            if (keyStore.isKeyEntry(sAlias)) {
                // Get the entry's password (we may already know it from
                // the wrapper)
                char[] cPassword = m_keyStoreWrap.getEntryPassword(sAlias);

                if (cPassword == null) {
                    cPassword = PKCS12_DUMMY_PASSWORD;

                    // Password is only relevant if the keystore is not
                    // PKCS #12
                    if (!keyStore.getType().equals(
                        KeyStoreType.PKCS12.toString()))
                    {
                        DGetPassword dGetPassword = new DGetPassword(
                            this,
                            m_res.getString("FPortecle.KeyEntryPassword.Title"),
                            true);
                        dGetPassword.setLocationRelativeTo(this);
                        dGetPassword.setVisible(true);
                        cPassword = dGetPassword.getPassword();

                        if (cPassword == null) {
                            return false;
                        }
                    }
                }

                // Do the copy
                Key key = keyStore.getKey(sAlias, cPassword);
                Certificate[] certs = keyStore.getCertificateChain(sAlias);
                keyStore.setKeyEntry(sNewAlias, key, cPassword, certs);

                // Update the keystore wrapper
                m_keyStoreWrap.setEntryPassword(sNewAlias, cPassword);
            }
            // ...if the entry is a trusted certificate
            else {
                // Do the copy
                Certificate cert = keyStore.getCertificate(sAlias);
                keyStore.setCertificateEntry(sNewAlias, cert);
            }

            // Delete the old entry
            keyStore.deleteEntry(sAlias);

            // Update the keystore wrapper
            m_keyStoreWrap.removeEntryPassword(sAlias);
            m_keyStoreWrap.setChanged(true);
        }
        catch (Exception ex) {
            displayException(ex);
            return false;
        }

        // Update the frame's components and title
        updateControls();
        updateTitle();

        return true;
    }

    /**
     * Update the application's controls dependant on the state of its keystore
     * (eg if changes to keystore are saved disable save toolbar button).
     */
    private void updateControls()
    {
        // keystore must have been loaded
        assert m_keyStoreWrap != null;
        assert m_keyStoreWrap.getKeyStore() != null;

        // Has keystore been saved?
        if (m_keyStoreWrap.isChanged()) {
            m_saveKeyStoreAction.setEnabled(true);
        }
        else {
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

        // Get keystore
        KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        try {
            // Update keystore entries table
            ((KeyStoreTableModel) m_jtKeyStore.getModel()).load(m_keyStoreWrap.getKeyStore());
        }
        catch (CryptoException ex) {
            displayException(ex);
        }
        catch (KeyStoreException ex) {
            displayException(ex);
        }

        // Passwords are not relevant for PKCS #12 keystores
        if (keyStore.getType().equals(KeyStoreType.PKCS12.toString())) {
            m_jmiSetKeyPairPass.setEnabled(false);
        }
        else {
            m_jmiSetKeyPairPass.setEnabled(true);
        }

        // Change keystore type menu items dependant on keystore type

        // Enable change keystore type menu
        m_jmChangeKeyStoreType.setEnabled(true);

        // Initially enable the menu items for all available types
        m_jmiChangeKeyStoreTypeJks.setEnabled(KeyStoreUtil.isAvailable(KeyStoreType.JKS));
        m_jmiChangeKeyStoreTypeCaseExactJks.setEnabled(KeyStoreUtil.isAvailable(KeyStoreType.CaseExactJKS));
        m_jmiChangeKeyStoreTypeJceks.setEnabled(KeyStoreUtil.isAvailable(KeyStoreType.JCEKS));
        m_jmiChangeKeyStoreTypePkcs12.setEnabled(true);
        m_jmiChangeKeyStoreTypeBks.setEnabled(true);
        m_jmiChangeKeyStoreTypeUber.setEnabled(true);
        m_jmiChangeKeyStoreTypeGkr.setEnabled(KeyStoreUtil.isAvailable(KeyStoreType.GKR));

        // Disable the menu item matching current keystore type
        String sType = keyStore.getType();

        if (sType.equals(KeyStoreType.JKS.toString())) {
            m_jmiChangeKeyStoreTypeJks.setEnabled(false);
        }
        else if (sType.equals(KeyStoreType.CaseExactJKS.toString())) {
            m_jmiChangeKeyStoreTypeCaseExactJks.setEnabled(false);
        }
        else if (sType.equals(KeyStoreType.JCEKS.toString())) {
            m_jmiChangeKeyStoreTypeJceks.setEnabled(false);
        }
        else if (sType.equals(KeyStoreType.PKCS12.toString())) {
            m_jmiChangeKeyStoreTypePkcs12.setEnabled(false);
        }
        else if (sType.equals(KeyStoreType.BKS.toString())) {
            m_jmiChangeKeyStoreTypeBks.setEnabled(false);
        }
        else if (sType.equals(KeyStoreType.UBER.toString())) {
            m_jmiChangeKeyStoreTypeUber.setEnabled(false);
        }
        else if (sType.equals(KeyStoreType.GKR.toString())) {
            m_jmiChangeKeyStoreTypeGkr.setEnabled(false);
        }
    }

    /**
     * Update the application's controls dependant on the state of its
     * keystore.
     */
    private void updateTitle()
    {
        // Application name
        String sAppName = m_res.getString("FPortecle.Title");

        // No keystore loaded so just display the application name
        if (m_keyStoreWrap == null) {
            setTitle(sAppName);
        }
        else {
            File fKeyStore = m_keyStoreWrap.getKeyStoreFile();

            // A newly created keystore is loaded - display Untitled string 
            // and app name
            if (fKeyStore == null) {
                setTitle(MessageFormat.format("[{0}] - {1}", new Object[] {
                    m_res.getString("FPortecle.Untitled"), sAppName }));
            }
            else {
                // Modified keystore loaded - display keystore file path,
                // "modified" indicator, and app name
                if (m_keyStoreWrap.isChanged()) {
                    setTitle(MessageFormat.format("{0}{1} - {2}",
                        new Object[] { fKeyStore,
                            m_res.getString("FPortecle.Modified"), sAppName }));
                }
                // Saved keystore loaded - display keystore file path and app name
                else {
                    setTitle(MessageFormat.format("{0} - {1}", new Object[] {
                        fKeyStore, sAppName }));
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
     * Set the text in the staus bar to reflect the status of the currently
     * loaded keystore.
     */
    public void setDefaultStatusBarText()
    {
        // No keystore loaded...
        if (m_keyStoreWrap == null) {
            setStatusBarText(m_res.getString("FPortecle.noKeyStore.statusbar"));
        }
        // keystore loaded...
        else {
            // Get the keystore and display information on its type and size
            KeyStore ksLoaded = m_keyStoreWrap.getKeyStore();

            int iSize;
            try {
                iSize = ksLoaded.size();
            }
            catch (KeyStoreException ex) {
                setStatusBarText("");
                displayException(ex);
                return;
            }

            String sType = ksLoaded.getType();
            try {
                sType = KeyStoreType.getInstance(sType).toPrettyString();
            }
            catch (CryptoException e) {
                // Ignore
            }

            String sProv = ksLoaded.getProvider().getName();

            if (iSize == 1) {
                setStatusBarText(MessageFormat.format(
                    m_res.getString("FPortecle.entry.statusbar"),
                    new String[] { sType, sProv }));
            }
            else {
                setStatusBarText(MessageFormat.format(
                    m_res.getString("FPortecle.entries.statusbar"),
                    new String[] { sType, sProv, "" + iSize }));
            }
        }
    }

    /**
     * Save the application preferences.
     */
    private void saveAppPrefs()
    {
        try {
            // The size of the keystore table panel - determines the size
            // of the main frame
            m_appPrefs.putInt(m_res.getString("AppPrefs.TableWidth"),
                m_jpKeyStoreTable.getWidth());
            m_appPrefs.putInt(m_res.getString("AppPrefs.TableHeight"),
                m_jpKeyStoreTable.getHeight());

            // The size of the keystore table's alias column - determines
            // the size of all of the table's columns
            m_appPrefs.putInt(m_res.getString("AppPrefs.AliasWidth"),
                m_jtKeyStore.getColumnModel().getColumn(1).getWidth());

            // Application's position on the desktop
            m_appPrefs.putInt(m_res.getString("AppPrefs.XPos"), this.getX());
            m_appPrefs.putInt(m_res.getString("AppPrefs.YPos"), this.getY());

            // Use CA certificates file?
            m_appPrefs.putBoolean(m_res.getString("AppPrefs.UseCaCerts"),
                m_bUseCaCerts);

            // CA Certificates file
            m_appPrefs.put(m_res.getString("AppPrefs.CaCertsFile"),
                m_fCaCertsFile.toString());

            // Show splash screen?
            m_appPrefs.putBoolean(m_res.getString("AppPrefs.SplashScreen"),
                m_bSplashScreen);

            // Recent files
            File[] fRecentFiles = m_jmrfFile.getRecentFiles();
            for (int iCnt = 0; iCnt < fRecentFiles.length; iCnt++) {
                m_appPrefs.put(m_res.getString("AppPrefs.RecentFile")
                    + (iCnt + 1), fRecentFiles[iCnt].toString());
            }

            // Look & feel
            LookAndFeel currentLookAndFeel = UIManager.getLookAndFeel();

            if (m_lookFeelOptions != null) {
                // Setting made in options
                m_appPrefs.put(m_res.getString("AppPrefs.LookFeel"),
                    m_lookFeelOptions.getClassName());
            }
            else {
                // Current setting
                if (currentLookAndFeel != null) {
                    UIManager.LookAndFeelInfo[] lookFeelInfos = UIManager.getInstalledLookAndFeels();

                    for (int iCnt = 0; iCnt < lookFeelInfos.length; iCnt++) {
                        UIManager.LookAndFeelInfo lookFeelInfo = lookFeelInfos[iCnt];

                        // Store current look & feel class name
                        if (currentLookAndFeel != null
                            && currentLookAndFeel.getName().equals(
                                lookFeelInfo.getName()))
                        {
                            m_appPrefs.put(
                                m_res.getString("AppPrefs.LookFeel"),
                                lookFeelInfo.getClassName());
                            break;
                        }
                    }
                }
            }

            // Use Look & Feel's decoration?
            if (m_bLookFeelDecorationOptions != null) {
                // Setting made in options
                m_appPrefs.putBoolean(
                    m_res.getString("AppPrefs.LookFeelDecor"),
                    m_bLookFeelDecorationOptions.booleanValue());
            }
            else {
                // Current setting
                m_appPrefs.putBoolean(
                    m_res.getString("AppPrefs.LookFeelDecor"),
                    JFrame.isDefaultLookAndFeelDecorated());
            }

            m_appPrefs.sync();
        }
        catch (Exception ex) {
            displayException(ex);
        }
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

        try {
            actualJreVersion = new JavaVersion(sJreVersion);
        }
        catch (VersionException ex) {
            // Could not parse JRE version
            String sMessage = MessageFormat.format(
                m_res.getString("FPortecle.NoParseJreVersion.message"),
                new String[] { sJreVersion });
            System.err.println(sMessage);
            JOptionPane.showMessageDialog(new JFrame(), sMessage,
                m_res.getString("FPortecle.Title"), JOptionPane.ERROR_MESSAGE);
            return false;
        }

        // Get the required Java Runtime Environment version
        JavaVersion reqJreVersion = null;

        try {
            reqJreVersion = new JavaVersion(REQ_JRE_VERSION);
        }
        catch (VersionException ex) {
            // Could not parse JRE version
            String sMessage = MessageFormat.format(
                m_res.getString("FPortecle.NoParseJreVersion.message"),
                new String[] { sJreVersion });
            System.err.println(sMessage);
            JOptionPane.showMessageDialog(new JFrame(), sMessage,
                m_res.getString("FPortecle.Title"), JOptionPane.ERROR_MESSAGE);
            return false;
        }

        // JRE version < 1.4.0
        if (actualJreVersion.compareTo(reqJreVersion) < 0) {
            // It isn't - warn the user and exit
            String sMessage = MessageFormat.format(
                m_res.getString("FPortecle.MinJreVersionReq.message"),
                new Object[] { actualJreVersion, reqJreVersion });
            System.err.println(sMessage);
            JOptionPane.showMessageDialog(new JFrame(), sMessage,
                m_res.getString("FPortecle.Title"), JOptionPane.ERROR_MESSAGE);
            return false;
        }
        // else JRE version => 1.4.0
        return true;
    }

    /**
     * Exit the application.
     */
    private void exitApplication()
    {
        // Does the current keystore contain unsaved changes?
        if (needSave()) {
            // Yes - ask the user if it should be saved
            int iWantSave = wantSave();

            if (iWantSave == JOptionPane.YES_OPTION) {
                // Save it
                saveKeyStore();
            }
            else if (iWantSave == JOptionPane.CANCEL_OPTION) {
                // May be exiting because of L&F change
                m_lookFeelOptions = null;
                m_bLookFeelDecorationOptions = null;

                return;
            }
        }

        // Save application preferences
        saveAppPrefs();

        System.exit(0);
    }

    /**
     * Initialise the application's look and feel.
     */
    private static void initLookAndFeel()
    {
        /* Set the theme used by the Metal look and feel to be "Light Metal" -
         this gets rid of the naff bold text used by the default Metal theme
         */
        MetalLookAndFeel.setCurrentTheme(METAL_THEME);

        // Install extra look and feels (which may or may not be present)
        String[] plafs = m_res.getString("FPortecle.AdditionalLookAndFeels").split("[\\s,]+");
        for (int i = 0, len = plafs.length; i < len; i++) {
            installLookFeel(plafs[i]);
        }

        try {
            // Use the look and feel
            UIManager.setLookAndFeel(m_appPrefs.get(
                m_res.getString("AppPrefs.LookFeel"),
                FPortecle.DEFAULT_LOOK_FEEL));
        }
        // Didn't work - no matter
        catch (UnsupportedLookAndFeelException e) {
        }
        catch (ClassNotFoundException e) {
        }
        catch (InstantiationException e) {
        }
        catch (IllegalAccessException e) {
        }

        // Use look & feel's decoration?
        boolean bLookFeelDecorated = m_appPrefs.getBoolean(
            m_res.getString("AppPrefs.LookFeelDecor"), false);

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
        try {
            // Get the name of the Look and Feel by instantiating an instance
            // of the class
            Class lookFeelClass = Class.forName(sLookFeelClassName);
            Constructor lookFeelConstructor = lookFeelClass.getConstructor(new Class[] {});
            LookAndFeel lookAndFeel = (LookAndFeel) lookFeelConstructor.newInstance(new Object[] {});

            // Install Look and Feel
            UIManager.installLookAndFeel(lookAndFeel.getName(),
                sLookFeelClassName);
        }
        catch (ClassNotFoundException e) {
        }
        catch (NoSuchMethodException e) {
        }
        catch (InstantiationException e) {
        }
        catch (IllegalAccessException e) {
        }
        catch (InvocationTargetException e) {
        }
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
        glassPane.addMouseListener(new MouseAdapter()
        {
        });
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
     * Gets a resource image.
     *
     * @param key the image's key
     * @return the Image corresponding to the key
     */
    private Image getResImage(String key)
    {
        return Toolkit.getDefaultToolkit().createImage(
            FPortecle.class.getResource(m_res.getString(key)));
    }

    /**
     * File overwrite confirmation dialog.
     *
     * @param file the file possibly being overwritten
     * @param title window title
     * @return true if the write operation should continue
     */
    private boolean confirmOverwrite(File file, String title)
    {
        if (file.isFile()) {
            String sMessage = MessageFormat.format(
                m_res.getString("FPortecle.OverWriteFile.message"),
                new String[] { file.getName() });
            int iSelected = JOptionPane.showConfirmDialog(this, sMessage,
                title, JOptionPane.YES_NO_OPTION);
            return iSelected == JOptionPane.YES_OPTION;
        }
        return true;
    }

    /**
     * Action to create a new keystore.
     */
    private class NewKeyStoreAction
        extends AbstractAction
    {
        /**
         * Construct action.
         */
        public NewKeyStoreAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString(
                "FPortecle.NewKeyStoreAction.accelerator").charAt(0),
                InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION,
                m_res.getString("FPortecle.NewKeyStoreAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString(
                "FPortecle.NewKeyStoreAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FPortecle.NewKeyStoreAction.text"));
            putValue(SHORT_DESCRIPTION,
                m_res.getString("FPortecle.NewKeyStoreAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(
                getResImage("FPortecle.NewKeyStoreAction.image")));
            setEnabled(true);
        }

        /**
         * Perform action.
         */
        public void act()
        {
            newKeyStore();
        }
    }

    /**
     * Action to save a keystore.
     */
    private class SaveKeyStoreAction
        extends AbstractAction
    {
        /**
         * Construct action.
         */
        public SaveKeyStoreAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString(
                "FPortecle.SaveKeyStoreAction.accelerator").charAt(0),
                InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION,
                m_res.getString("FPortecle.SaveKeyStoreAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString(
                "FPortecle.SaveKeyStoreAction.mnemonic").charAt(0)));
            putValue(NAME,
                m_res.getString("FPortecle.SaveKeyStoreAction.text"));
            putValue(SHORT_DESCRIPTION,
                m_res.getString("FPortecle.SaveKeyStoreAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(
                getResImage("FPortecle.SaveKeyStoreAction.image")));
            setEnabled(false);
        }

        /**
         * Perform action.
         */
        public void act()
        {
            saveKeyStore();
        }
    }

    /**
     * Action to open a keystore file.
     */
    private class OpenKeyStoreFileAction
        extends AbstractAction
    {
        /**
         * Construct action.
         */
        public OpenKeyStoreFileAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString(
                "FPortecle.OpenKeyStoreFileAction.accelerator").charAt(0),
                InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION,
                m_res.getString("FPortecle.OpenKeyStoreFileAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString(
                "FPortecle.OpenKeyStoreFileAction.mnemonic").charAt(0)));
            putValue(NAME,
                m_res.getString("FPortecle.OpenKeyStoreFileAction.text"));
            putValue(SHORT_DESCRIPTION,
                m_res.getString("FPortecle.OpenKeyStoreFileAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(
                getResImage("FPortecle.OpenKeyStoreFileAction.image")));
            setEnabled(true);
        }

        /**
         * Perform action.
         */
        public void act()
        {
            openKeyStoreFile();
        }
    }

    /**
     * Action to generate a key pair.
     */
    private class GenKeyPairAction
        extends AbstractAction
    {
        /**
         * Construct action.
         */
        public GenKeyPairAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString(
                "FPortecle.GenKeyPairAction.accelerator").charAt(0),
                InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION,
                m_res.getString("FPortecle.GenKeyPairAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString(
                "FPortecle.GenKeyPairAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FPortecle.GenKeyPairAction.text"));
            putValue(SHORT_DESCRIPTION,
                m_res.getString("FPortecle.GenKeyPairAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(
                getResImage("FPortecle.GenKeyPairAction.image")));
            setEnabled(false);
        }

        /**
         * Perform action.
         */
        public void act()
        {
            generateKeyPair();
        }
    }

    /**
     * Action to import a trusted certificate.
     */
    private class ImportTrustCertAction
        extends AbstractAction
    {
        /**
         * Construct action.
         */
        public ImportTrustCertAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString(
                "FPortecle.ImportTrustCertAction.accelerator").charAt(0),
                InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION,
                m_res.getString("FPortecle.ImportTrustCertAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString(
                "FPortecle.ImportTrustCertAction.mnemonic").charAt(0)));
            putValue(NAME,
                m_res.getString("FPortecle.ImportTrustCertAction.text"));
            putValue(SHORT_DESCRIPTION,
                m_res.getString("FPortecle.ImportTrustCertAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(
                getResImage("FPortecle.ImportTrustCertAction.image")));
            setEnabled(false);
        }

        /**
         * Perform action.
         */
        public void act()
        {
            importTrustedCert();
        }
    }

    /**
     * Action to import a key pair.
     */
    private class ImportKeyPairAction
        extends AbstractAction
    {
        /**
         * Construct action.
         */
        public ImportKeyPairAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString(
                "FPortecle.ImportKeyPairAction.accelerator").charAt(0),
                InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION,
                m_res.getString("FPortecle.ImportKeyPairAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString(
                "FPortecle.ImportKeyPairAction.mnemonic").charAt(0)));
            putValue(NAME,
                m_res.getString("FPortecle.ImportKeyPairAction.text"));
            putValue(SHORT_DESCRIPTION,
                m_res.getString("FPortecle.ImportKeyPairAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(
                getResImage("FPortecle.ImportKeyPairAction.image")));
            setEnabled(false);
        }

        /**
         * Perform action.
         */
        public void act()
        {
            importKeyPair();
        }
    }

    /**
     * Action to set a keystore password.
     */
    private class SetKeyStorePassAction
        extends AbstractAction
    {
        /**
         * Construct action.
         */
        public SetKeyStorePassAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString(
                "FPortecle.SetKeyStorePassAction.accelerator").charAt(0),
                InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION,
                m_res.getString("FPortecle.SetKeyStorePassAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString(
                "FPortecle.SetKeyStorePassAction.mnemonic").charAt(0)));
            putValue(NAME,
                m_res.getString("FPortecle.SetKeyStorePassAction.text"));
            putValue(SHORT_DESCRIPTION,
                m_res.getString("FPortecle.SetKeyStorePassAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(
                getResImage("FPortecle.SetKeyStorePassAction.image")));
            setEnabled(false);
        }

        /**
         * Perform action.
         */
        public void act()
        {
            setKeyStorePassword();
        }
    }

    /**
     * Action to show a keystore report.
     */
    private class KeyStoreReportAction
        extends AbstractAction
    {
        /**
         * Construct action.
         */
        public KeyStoreReportAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString(
                "FPortecle.KeyStoreReportAction.accelerator").charAt(0),
                InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION,
                m_res.getString("FPortecle.KeyStoreReportAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString(
                "FPortecle.KeyStoreReportAction.mnemonic").charAt(0)));
            putValue(NAME,
                m_res.getString("FPortecle.KeyStoreReportAction.text"));
            putValue(SHORT_DESCRIPTION,
                m_res.getString("FPortecle.KeyStoreReportAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(
                getResImage("FPortecle.KeyStoreReportAction.image")));
            setEnabled(false);
        }

        /**
         * Perform action.
         */
        public void act()
        {
            keyStoreReport();
        }
    }

    /**
     * Action to examine a certificate.
     */
    private class ExamineCertAction
        extends AbstractAction
    {
        /**
         * Construct action.
         */
        public ExamineCertAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString(
                "FPortecle.ExamineCertAction.accelerator").charAt(0),
                InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION,
                m_res.getString("FPortecle.ExamineCertAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString(
                "FPortecle.ExamineCertAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FPortecle.ExamineCertAction.text"));
            putValue(SHORT_DESCRIPTION,
                m_res.getString("FPortecle.ExamineCertAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(
                getResImage("FPortecle.ExamineCertAction.image")));
            setEnabled(true);
        }

        /**
         * Perform action.
         */
        public void act()
        {
            examineCert();
        }
    }

    /**
     * Action to examine a SSL/TLS connection.
     */
    private class ExamineCertSSLAction
        extends AbstractAction
    {
        /**
         * Construct action.
         */
        public ExamineCertSSLAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString(
                "FPortecle.ExamineCertSSLAction.accelerator").charAt(0),
                InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION,
                m_res.getString("FPortecle.ExamineCertSSLAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString(
                "FPortecle.ExamineCertSSLAction.mnemonic").charAt(0)));
            putValue(NAME,
                m_res.getString("FPortecle.ExamineCertSSLAction.text"));
            putValue(SHORT_DESCRIPTION,
                m_res.getString("FPortecle.ExamineCertSSLAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(
                getResImage("FPortecle.ExamineCertSSLAction.image")));
            setEnabled(true);
        }

        /**
         * Perform action.
         */
        public void act()
        {
            examineCertSSL();
        }
    }

    /**
     * Action to examine a CSR.
     */
    private class ExamineCsrAction
        extends AbstractAction
    {
        /**
         * Construct action.
         */
        public ExamineCsrAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString(
                "FPortecle.ExamineCsrAction.accelerator").charAt(0),
                InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION,
                m_res.getString("FPortecle.ExamineCsrAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString(
                "FPortecle.ExamineCsrAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FPortecle.ExamineCsrAction.text"));
            putValue(SHORT_DESCRIPTION,
                m_res.getString("FPortecle.ExamineCsrAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(
                getResImage("FPortecle.ExamineCsrAction.image")));
            setEnabled(true);
        }

        /**
         * Perform action.
         */
        public void act()
        {
            examineCSR();
        }
    }

    /**
     * Action to examine a CRL.
     */
    private class ExamineCrlAction
        extends AbstractAction
    {
        /**
         * Construct action.
         */
        public ExamineCrlAction()
        {
            putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(m_res.getString(
                "FPortecle.ExamineCrlAction.accelerator").charAt(0),
                InputEvent.CTRL_MASK));
            putValue(LONG_DESCRIPTION,
                m_res.getString("FPortecle.ExamineCrlAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString(
                "FPortecle.ExamineCrlAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FPortecle.ExamineCrlAction.text"));
            putValue(SHORT_DESCRIPTION,
                m_res.getString("FPortecle.ExamineCrlAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(
                getResImage("FPortecle.ExamineCrlAction.image")));
            setEnabled(true);
        }

        /**
         * Perform action.
         */
        public void act()
        {
            examineCRL();
        }
    }

    /**
     * Action to show help.
     */
    private class HelpAction
        extends AbstractAction
    {
        /**
         * Construct action.
         */
        public HelpAction()
        {
            putValue(ACCELERATOR_KEY,
                KeyStroke.getKeyStroke(KeyEvent.VK_F1, 0));
            putValue(LONG_DESCRIPTION,
                m_res.getString("FPortecle.HelpAction.statusbar"));
            putValue(MNEMONIC_KEY, new Integer(m_res.getString(
                "FPortecle.HelpAction.mnemonic").charAt(0)));
            putValue(NAME, m_res.getString("FPortecle.HelpAction.text"));
            putValue(SHORT_DESCRIPTION,
                m_res.getString("FPortecle.HelpAction.tooltip"));
            putValue(SMALL_ICON, new ImageIcon(
                getResImage("FPortecle.HelpAction.image")));
            setEnabled(true);
        }

        /**
         * Perform action.
         */
        public void act()
        {
            showHelp();
        }
    }

    /**
     * Action helper class.
     */
    private abstract class AbstractAction
        extends javax.swing.AbstractAction
    {
        protected abstract void act();

        public void actionPerformed(ActionEvent evt)
        {
            setDefaultStatusBarText();
            setCursorBusy();
            repaint();
            new Thread(new Runnable()
            {
                public void run()
                {
                    try {
                        act();
                    }
                    finally {
                        setCursorFree();
                    }
                }
            }).start();
        }
    }

    /**
     * ActionListener helper class.
     */
    private abstract class ActionListener
        implements java.awt.event.ActionListener
    {
        protected abstract void act();

        public void actionPerformed(ActionEvent evt)
        {
            setDefaultStatusBarText();
            setCursorBusy();
            repaint();
            new Thread(new Runnable()
            {
                public void run()
                {
                    try {
                        act();
                    }
                    finally {
                        setCursorFree();
                    }
                }
            }).start();
        }
    }

    /**
     * Runnable to create and show Portecle GUI.
     */
    private static class CreateAndShowGui
        implements Runnable
    {

        /** Keystore file to open initially */
        private File m_fKeyStore;

        /**
         * Construct CreateAndShowGui.
         *
         * @param fKeyStore Keystore file to open initially (supply null
         * if none)
         */
        public CreateAndShowGui(File fKeyStore)
        {
            m_fKeyStore = fKeyStore;
        }

        /**
         * Create and show Portecle GUI.
         */
        public void run()
        {
            initLookAndFeel();
            FPortecle fPortecle = new FPortecle();
            fPortecle.setVisible(true);
            if (m_fKeyStore != null) {
                fPortecle.openKeyStoreFile(m_fKeyStore);
            }
        }
    }

    /**
     * Start the Portecle application.  Takes one optional argument -
     * the location of a keystore file to open upon startup.
     *
     * @param args the command line arguments
     */
    public static void main(String[] args)
    {
        // Check that the correct JRE is being used
        if (!checkJRE()) {
            System.exit(1);
        }

        try {
            Provider bcProv = Security.getProvider("BC");
            
            if (bcProv == null) {
                // Instantiate the Bouncy Castle provider
                Class bcProvClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                bcProv = (Provider) bcProvClass.newInstance();

                // Add BC as a security provider
                Security.addProvider(bcProv);
            }

            // Check BC version
            Double bcVer = new Double(bcProv.getVersion());
            if (REQ_BC_VERSION.compareTo(bcVer) > 0) {
                JOptionPane.showMessageDialog(new JFrame(),
                    MessageFormat.format(
                        m_res.getString("FPortecle.NoBcVersion.message"),
                        new Object[] { REQ_BC_VERSION, bcVer }),
                    m_res.getString("FPortecle.Title"),
                    JOptionPane.WARNING_MESSAGE);
            }
        }
        catch (Throwable thw) {
            // No sign of the provider - warn the user and exit
            System.err.println(m_res.getString("FPortecle.NoLoadBc.message"));
            thw.printStackTrace();
            JOptionPane.showMessageDialog(new JFrame(),
                m_res.getString("FPortecle.NoLoadBc.message"),
                m_res.getString("FPortecle.Title"), JOptionPane.ERROR_MESSAGE);
            System.exit(1);
        }

        // Install additional providers
        String[] additionalProviders =
            m_res.getString("FPortecle.AdditionalProviders").split("[\\s,]+");
        for (int i = 0, len = additionalProviders.length; i < len; i++) {
            String[] prov = additionalProviders[i].split(":+", 2);
            if (Security.getProvider(prov[0]) == null) {
                try {
                    Class provClass = Class.forName(prov[1]);
                    Security.addProvider((Provider) provClass.newInstance());
                }
                catch (Throwable t) {
                    // TODO: should maybe notify in some cases?
                    // Eg. Throwable, but not Exception?
                }
            }
        }
        
        m_bSplashScreen = m_appPrefs.getBoolean(
            m_res.getString("AppPrefs.SplashScreen"), true);

        if (m_bSplashScreen) {
            // Create and display a splash screen
            WSplash wSplash = new WSplash(
                Toolkit.getDefaultToolkit().createImage(
                    ClassLoader.getSystemResource(m_res.getString("FPortecle.Splash.image"))),
                3000);
            // Wait for the splash screen to disappear
            while (wSplash.isVisible()) {
                try {
                    Thread.sleep(500);
                }
                catch (InterruptedException ex) {
                    // Do nothing
                }
            }
        }

        /* If arguments have been supplied treat the first one as a
         keystore file */
        File fKeyStore = null;
        if (args.length != 0) {
            fKeyStore = new File(args[0]);
        }

        // Create and show GUI on the event handler thread
        SwingUtilities.invokeLater(new CreateAndShowGui(fKeyStore));
    }
}
