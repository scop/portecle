/*
 * FPortecle.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004-2017 Ville Skyttä, ville.skytta@iki.fi
 *             2010 Lam Chau, lamchau@gmail.com
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
import java.awt.datatransfer.Transferable;
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
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.prefs.Preferences;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import javax.swing.Action;
import javax.swing.DefaultCellEditor;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
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
import javax.swing.ListSelectionModel;
import javax.swing.LookAndFeel;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.WindowConstants;
import javax.swing.border.BevelBorder;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableColumn;

import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import net.sf.portecle.crypto.CryptoException;
import net.sf.portecle.crypto.KeyPairType;
import net.sf.portecle.crypto.KeyStoreType;
import net.sf.portecle.crypto.KeyStoreUtil;
import net.sf.portecle.crypto.ProviderUtil;
import net.sf.portecle.crypto.X509CertUtil;
import net.sf.portecle.gui.AppleApplicationHelper;
import net.sf.portecle.gui.DesktopUtil;
import net.sf.portecle.gui.JMenuItemRecentFile;
import net.sf.portecle.gui.JMenuRecentFiles;
import net.sf.portecle.gui.LastDir;
import net.sf.portecle.gui.SingleFileDropHelper;
import net.sf.portecle.gui.SwingHelper;
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

import static java.util.Arrays.asList;

/**
 * Start class and main frame of Portecle.
 */
public class FPortecle
    extends JFrame
    implements StatusBar
{
	/** Resource bundle base name */
	private static final String RB_BASENAME = FPortecle.class.getPackage().getName() + "/resources";

	/** Resource bundle */
	public static final ResourceBundle RB = ResourceBundle.getBundle(RB_BASENAME);

	/** Logger */
	public static final Logger LOG = Logger.getLogger(FPortecle.class.getName(), RB_BASENAME);

	/** Application preferences */
	private static final Preferences PREFS = Preferences.userNodeForPackage(FPortecle.class);

	/** Minimum required BC version */
	private static final Double REQ_BC_VERSION = 1.56;

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
	private static final int RECENT_FILES_INDEX = EXPERIMENTAL ? 7 : 6;

	/** Default look &amp; feel class name */
	private static final String DEFAULT_LOOK_FEEL = UIManager.getCrossPlatformLookAndFeelClassName();

	/** Default CA certificates keystore file */
	/* package private */static final File DEFAULT_CA_CERTS_FILE = new File(System.getProperty("java.home"),
	    "lib" + File.separator + "security" + File.separator + FileChooserFactory.CACERTS_FILENAME);

	/** The last directory accessed by the application */
	private final LastDir m_lastDir = new LastDir();

	/** Use CA certificates keystore file? */
	private boolean m_bUseCaCerts;

	/** CA certificates keystore file */
	private File m_fCaCertsFile;

	/** CA certificates keystore */
	private KeyStore m_caCertsKeyStore;

	/** KeystoreWrapper object containing the current keystore */
	private KeyStoreWrapper m_keyStoreWrap;

	/** The PRNG, cached for performance reasons */
	private SecureRandom m_rnd;

	/** Frame for Help System */
	private FHelp m_fHelp;

	/** Look &amp; Feel setting made in options (picked up by saveAppPrefs) */
	private String lookFeelClassName;

	/** Look &amp; Feel setting made in options (picked up by saveAppPrefs) */
	private Boolean m_bLookFeelDecorationOptions;

	/** Preference: allowed to set BC org.bouncycastle.asn1.allow_unsafe_integer  
            made in options (picked up by saveAppPrefs) */
	private Boolean m_bBouncyCastleAllowUnsafeInteger;

	/** Currently selected alias */
	private String selectedAlias;

	// //////////////////////////////////////////////////////////
	// Menu bar controls
	// //////////////////////////////////////////////////////////

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

	/** BKS-V1 menu item in Change Keystore Type menu */
	private JMenuItem m_jmiChangeKeyStoreTypeBksV1;

	/** UBER menu item in Change Keystore Type menu */
	private JMenuItem m_jmiChangeKeyStoreTypeUber;

	/** BCFKS menu item in Change Keystore Type menu */
	private JMenuItem m_jmiChangeKeyStoreTypeBcfks;

	/** GKR menu item in Change Keystore Type menu */
	private JMenuItem m_jmiChangeKeyStoreTypeGkr;

	// //////////////////////////////////////////////////////////
	// Pop-up menu controls
	// //////////////////////////////////////////////////////////

	/** Key entry pop-up menu */
	private JPopupMenu m_jpmKey;

	/** Key pair entry pop-up menu */
	private JPopupMenu m_jpmKeyPair;

	/** Set Password menu item of key pair entry pop-up menu */
	private JMenuItem m_jmiSetKeyPairPass;

	/** Trusted Certificate entry pop-up menu */
	private JPopupMenu m_jpmCert;

	// //////////////////////////////////////////////////////////
	// Keystore table controls
	// //////////////////////////////////////////////////////////

	/** Panel to hold keystore entries table */
	private JPanel m_jpKeyStoreTable;

	/** Keystore entries table */
	private KeyStoreTable m_jtKeyStore;

	// //////////////////////////////////////////////////////////
	// Status bar controls
	// //////////////////////////////////////////////////////////

	/** Label to display current application status messages */
	private JLabel m_jlStatusBar;

	// //////////////////////////////////////////////////////////
	// Actions - these are shared between the menu and toolbar
	// //////////////////////////////////////////////////////////

	/** New Keystore action */
	private final NewKeyStoreAction m_newKeyStoreAction = new NewKeyStoreAction();

	/** Open Keystore File action */
	private final OpenKeyStoreFileAction m_openKeyStoreFileAction = new OpenKeyStoreFileAction();

	/** Open CA certs keystore File action */
	private final OpenCaCertsKeyStoreAction m_openCaCertsKeyStoreFileAction = new OpenCaCertsKeyStoreAction();

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
		m_bUseCaCerts = PREFS.getBoolean(RB.getString("AppPrefs.UseCaCerts"), false);
		m_fCaCertsFile =
		    new File(PREFS.get(RB.getString("AppPrefs.CaCertsFile"), DEFAULT_CA_CERTS_FILE.getAbsolutePath()));
		
		m_bBouncyCastleAllowUnsafeInteger = PREFS.getBoolean(RB.getString("AppPrefs.BouncyCastleAllowUnsafeInteger"), false);
		if(m_bBouncyCastleAllowUnsafeInteger)
		{
			System.getProperties().setProperty(RB.getString("AppPrefs.BouncyCastleAllowUnsafeIntegerOption"), "true");
		}

		// Initialize GUI components
		initComponents();
	}

	/**
	 * Initialize FPortecle frame's GUI components.
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
			@Override
			public void windowClosing(WindowEvent evt)
			{
				exitApplication();
			}
		});
		setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);

		updateTitle();
		pack();

		// Set application position according to application preferences unless the relevant preferences are
		// not present or are invalid
		int iXPos = PREFS.getInt(RB.getString("AppPrefs.XPos"), 0);
		int iYPos = PREFS.getInt(RB.getString("AppPrefs.YPos"), 0);

		if (iXPos <= 0 || iYPos <= 0)
		{
			// Center the frame in the center of the desktop
			setLocationRelativeTo(null);
		}
		else
		{
			// Use application property values for positioning
			setLocation(new Point(iXPos, iYPos));
		}

		// If frame is not completely visible then set it to default size and center it
		if (!SwingUtilities.isRectangleContainingRectangle(new Rectangle(Toolkit.getDefaultToolkit().getScreenSize()),
		    getBounds()))
		{
			m_jpKeyStoreTable.setPreferredSize(new Dimension(DEFAULT_TABLE_WIDTH, DEFAULT_TABLE_HEIGHT));
			setLocationRelativeTo(null);
		}

		setApplicationIcon();
	}

	private void setApplicationIcon()
	{
		setIconImages(asList(getResImage("FPortecle.Icon.image.16"),
				getResImage("FPortecle.Icon.image.32"),
				getResImage("FPortecle.Icon.image.64"),
				getResImage("FPortecle.Icon.image.96"),
				getResImage("FPortecle.Icon.image.128")));
		AppleApplicationHelper appleApplicationHelper = new AppleApplicationHelper();
		if (appleApplicationHelper.isAppleEnvironment())
		{
			appleApplicationHelper.setDockIconImage(getResImage("FPortecle.Icon.image.64"));
		}
	}

	/**
	 * Initialize FPortecle frame's main menu GUI components.
	 */
	private void initMenu()
	{
		// The menu items that carry out the same function as tool bar buttons use actions

		// The menu bar
		JMenuBar jmbMenuBar = new JMenuBar();

		// File menu
		m_jmrfFile =
		    new JMenuRecentFiles(RB.getString("FPortecle.m_jmrfFile.text"), RECENT_FILES_LENGTH, RECENT_FILES_INDEX);
		m_jmrfFile.setMnemonic(RB.getString("FPortecle.m_jmrfFile.mnemonic").charAt(0));

		JMenuItem jmiNewKeyStore = new JMenuItem(m_newKeyStoreAction);
		jmiNewKeyStore.setToolTipText(null);
		jmiNewKeyStore.addChangeListener(
		    new StatusBarChangeHandler((String) m_newKeyStoreAction.getValue(Action.LONG_DESCRIPTION), this));
		m_jmrfFile.add(jmiNewKeyStore);

		JMenuItem jmiOpenKeyStoreFile = new JMenuItem(m_openKeyStoreFileAction);
		jmiOpenKeyStoreFile.setToolTipText(null);
		jmiOpenKeyStoreFile.addChangeListener(
		    new StatusBarChangeHandler((String) m_openKeyStoreFileAction.getValue(Action.LONG_DESCRIPTION), this));
		m_jmrfFile.add(jmiOpenKeyStoreFile);

		if (EXPERIMENTAL)
		{
			JMenuItem jmiOpenKeyStorePkcs11 = new JMenuItem(RB.getString("FPortecle.jmiOpenKeyStorePkcs11.text"),
			    RB.getString("FPortecle.jmiOpenKeyStorePkcs11.mnemonic").charAt(0));
			jmiOpenKeyStorePkcs11.setIcon(new ImageIcon(getResImage("FPortecle.jmiOpenKeyStorePkcs11.image")));
			jmiOpenKeyStorePkcs11.setToolTipText(null);
			if (ProviderUtil.getPkcs11Providers().isEmpty())
			{
				jmiOpenKeyStorePkcs11.setEnabled(false);
			}
			m_jmrfFile.add(jmiOpenKeyStorePkcs11);
			jmiOpenKeyStorePkcs11.addActionListener(new ActionListener()
			{
				@Override
				protected void act()
				{
					openKeyStorePkcs11();
				}
			});
			jmiOpenKeyStorePkcs11.addChangeListener(
			    new StatusBarChangeHandler(RB.getString("FPortecle.jmiOpenKeyStorePkcs11.statusbar"), this));
		}

		JMenuItem jmiOpenCaCertsKeyStoreFile = new JMenuItem(m_openCaCertsKeyStoreFileAction);
		jmiOpenCaCertsKeyStoreFile.setToolTipText(null);
		jmiOpenCaCertsKeyStoreFile.addChangeListener(new StatusBarChangeHandler(
		    (String) m_openCaCertsKeyStoreFileAction.getValue(Action.LONG_DESCRIPTION), this));
		m_jmrfFile.add(jmiOpenCaCertsKeyStoreFile);

		m_jmrfFile.addSeparator();

		JMenuItem jmiSaveKeyStore = new JMenuItem(m_saveKeyStoreAction);
		jmiSaveKeyStore.setToolTipText(null);
		jmiSaveKeyStore.addChangeListener(
		    new StatusBarChangeHandler((String) m_saveKeyStoreAction.getValue(Action.LONG_DESCRIPTION), this));
		m_jmrfFile.add(jmiSaveKeyStore);

		m_jmiSaveKeyStoreAs = new JMenuItem(RB.getString("FPortecle.m_jmiSaveKeyStoreAs.text"),
		    RB.getString("FPortecle.m_jmiSaveKeyStoreAs.mnemonic").charAt(0));
		m_jmiSaveKeyStoreAs.setIcon(new ImageIcon(getResImage("FPortecle.m_jmiSaveKeyStoreAs.image")));
		m_jmiSaveKeyStoreAs.setEnabled(false);
		m_jmrfFile.add(m_jmiSaveKeyStoreAs);
		m_jmiSaveKeyStoreAs.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				saveKeyStoreAs();
			}
		});
		m_jmiSaveKeyStoreAs.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.m_jmiSaveKeyStoreAs.statusbar"), this));

		m_jmrfFile.addSeparator();

		// Add recent files to file menu
		for (int iCnt = RECENT_FILES_LENGTH; iCnt > 0; iCnt--)
		{
			String sRecentFile = PREFS.get(RB.getString("AppPrefs.RecentFile") + iCnt, null);

			if (sRecentFile != null)
			{
				m_jmrfFile.add(createRecentFileMenuItem(new File(sRecentFile)));
			}
		}

		JMenuItem jmiExit =
		    new JMenuItem(RB.getString("FPortecle.jmiExit.text"), RB.getString("FPortecle.jmiExit.mnemonic").charAt(0));
		jmiExit.setIcon(new ImageIcon(getResImage("FPortecle.jmiExit.image")));
		m_jmrfFile.add(jmiExit);
		jmiExit.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				exitApplication();
			}
		});
		jmiExit.addChangeListener(new StatusBarChangeHandler(RB.getString("FPortecle.jmiExit.statusbar"), this));

		// Tools menu
		JMenu jmTools = new JMenu(RB.getString("FPortecle.jmTools.text"));
		jmTools.setMnemonic(RB.getString("FPortecle.jmTools.mnemonic").charAt(0));

		JMenuItem jmiGenKeyPair = new JMenuItem(m_genKeyPairAction);
		jmiGenKeyPair.setToolTipText(null);
		jmiGenKeyPair.addChangeListener(
		    new StatusBarChangeHandler((String) m_genKeyPairAction.getValue(Action.LONG_DESCRIPTION), this));
		jmTools.add(jmiGenKeyPair);

		JMenuItem jmiImportTrustCert = new JMenuItem(m_importTrustCertAction);
		jmiImportTrustCert.setToolTipText(null);
		jmiImportTrustCert.addChangeListener(
		    new StatusBarChangeHandler((String) m_importTrustCertAction.getValue(Action.LONG_DESCRIPTION), this));
		jmTools.add(jmiImportTrustCert);

		JMenuItem jmiImportKeyPair = new JMenuItem(m_importKeyPairAction);
		jmiImportKeyPair.setToolTipText(null);
		jmiImportKeyPair.addChangeListener(
		    new StatusBarChangeHandler((String) m_importKeyPairAction.getValue(Action.LONG_DESCRIPTION), this));
		jmTools.add(jmiImportKeyPair);

		jmTools.addSeparator();

		JMenuItem jmiSetKeyStorePass = new JMenuItem(m_setKeyStorePassAction);
		jmiSetKeyStorePass.setToolTipText(null);
		jmiSetKeyStorePass.addChangeListener(
		    new StatusBarChangeHandler((String) m_setKeyStorePassAction.getValue(Action.LONG_DESCRIPTION), this));
		jmTools.add(jmiSetKeyStorePass);

		m_jmChangeKeyStoreType = new JMenu(RB.getString("FPortecle.m_jmChangeKeyStoreType.text"));
		m_jmChangeKeyStoreType.setIcon(new ImageIcon(getResImage("FPortecle.m_jmChangeKeyStoreType.image")));
		m_jmChangeKeyStoreType.setMnemonic(RB.getString("FPortecle.m_jmChangeKeyStoreType.mnemonic").charAt(0));
		m_jmChangeKeyStoreType.setEnabled(false);
		jmTools.add(m_jmChangeKeyStoreType);

		// Add Change Keystore Type sub-menu of Tools

		m_jmiChangeKeyStoreTypeJks = new JMenuItem(RB.getString("FPortecle.m_jmiChangeKeyStoreTypeJks.text"),
		    RB.getString("FPortecle.m_jmiChangeKeyStoreTypeJks.mnemonic").charAt(0));
		m_jmiChangeKeyStoreTypeJks.setEnabled(false);
		m_jmiChangeKeyStoreTypeJks.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				changeKeyStoreType(KeyStoreType.JKS);
			}
		});
		m_jmiChangeKeyStoreTypeJks.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.m_jmiChangeKeyStoreTypeJks.statusbar"), this));

		m_jmiChangeKeyStoreTypeCaseExactJks =
		    new JMenuItem(RB.getString("FPortecle.m_jmiChangeKeyStoreTypeCaseExactJks.text"),
		        RB.getString("FPortecle.m_jmiChangeKeyStoreTypeCaseExactJks.mnemonic").charAt(0));
		m_jmiChangeKeyStoreTypeCaseExactJks.setEnabled(false);
		m_jmiChangeKeyStoreTypeCaseExactJks.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				changeKeyStoreType(KeyStoreType.CaseExactJKS);
			}
		});
		m_jmiChangeKeyStoreTypeCaseExactJks.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.m_jmiChangeKeyStoreTypeCaseExactJks.statusbar"), this));

		m_jmiChangeKeyStoreTypeJceks = new JMenuItem(RB.getString("FPortecle.m_jmiChangeKeyStoreTypeJceks.text"),
		    RB.getString("FPortecle.m_jmiChangeKeyStoreTypeJceks.mnemonic").charAt(0));
		m_jmiChangeKeyStoreTypeJceks.setEnabled(false);
		m_jmiChangeKeyStoreTypeJceks.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				changeKeyStoreType(KeyStoreType.JCEKS);
			}
		});
		m_jmiChangeKeyStoreTypeJceks.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.m_jmiChangeKeyStoreTypeJceks.statusbar"), this));

		m_jmiChangeKeyStoreTypePkcs12 = new JMenuItem(RB.getString("FPortecle.m_jmiChangeKeyStoreTypePkcs12.text"),
		    RB.getString("FPortecle.m_jmiChangeKeyStoreTypePkcs12.mnemonic").charAt(0));
		m_jmiChangeKeyStoreTypePkcs12.setEnabled(false);
		m_jmiChangeKeyStoreTypePkcs12.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				changeKeyStoreType(KeyStoreType.PKCS12);
			}
		});
		m_jmiChangeKeyStoreTypePkcs12.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.m_jmiChangeKeyStoreTypePkcs12.statusbar"), this));

		m_jmiChangeKeyStoreTypeBks = new JMenuItem(RB.getString("FPortecle.m_jmiChangeKeyStoreTypeBks.text"),
		    RB.getString("FPortecle.m_jmiChangeKeyStoreTypeBks.mnemonic").charAt(0));
		m_jmiChangeKeyStoreTypeBks.setEnabled(false);
		m_jmiChangeKeyStoreTypeBks.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				changeKeyStoreType(KeyStoreType.BKS);
			}
		});
		m_jmiChangeKeyStoreTypeBks.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.m_jmiChangeKeyStoreTypeBks.statusbar"), this));

		m_jmiChangeKeyStoreTypeBksV1 = new JMenuItem(RB.getString("FPortecle.m_jmiChangeKeyStoreTypeBksV1.text"),
		    RB.getString("FPortecle.m_jmiChangeKeyStoreTypeBksV1.mnemonic").charAt(0));
		m_jmiChangeKeyStoreTypeBksV1.setEnabled(false);
		m_jmiChangeKeyStoreTypeBksV1.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				changeKeyStoreType(KeyStoreType.BKS_V1);
			}
		});
		m_jmiChangeKeyStoreTypeBksV1.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.m_jmiChangeKeyStoreTypeBksV1.statusbar"), this));

		m_jmiChangeKeyStoreTypeUber = new JMenuItem(RB.getString("FPortecle.m_jmiChangeKeyStoreTypeUber.text"),
		    RB.getString("FPortecle.m_jmiChangeKeyStoreTypeUber.mnemonic").charAt(0));
		m_jmiChangeKeyStoreTypeUber.setEnabled(false);
		m_jmiChangeKeyStoreTypeUber.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				changeKeyStoreType(KeyStoreType.UBER);
			}
		});
		m_jmiChangeKeyStoreTypeUber.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.m_jmiChangeKeyStoreTypeUber.statusbar"), this));

		m_jmiChangeKeyStoreTypeBcfks = new JMenuItem(RB.getString("FPortecle.m_jmiChangeKeyStoreTypeBcfks.text"),
		    RB.getString("FPortecle.m_jmiChangeKeyStoreTypeBcfks.mnemonic").charAt(0));
		m_jmiChangeKeyStoreTypeBcfks.setEnabled(false);
		m_jmiChangeKeyStoreTypeBcfks.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				changeKeyStoreType(KeyStoreType.BCFKS);
			}
		});
		m_jmiChangeKeyStoreTypeBcfks.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.m_jmiChangeKeyStoreTypeBcfks.statusbar"), this));

		m_jmiChangeKeyStoreTypeGkr = new JMenuItem(RB.getString("FPortecle.m_jmiChangeKeyStoreTypeGkr.text"),
		    RB.getString("FPortecle.m_jmiChangeKeyStoreTypeGkr.mnemonic").charAt(0));
		m_jmiChangeKeyStoreTypeGkr.setEnabled(false);
		m_jmiChangeKeyStoreTypeGkr.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				changeKeyStoreType(KeyStoreType.GKR);
			}
		});
		m_jmiChangeKeyStoreTypeGkr.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.m_jmiChangeKeyStoreTypeGkr.statusbar"), this));

		m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeJks);
		m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypePkcs12);
		m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeJceks);
		m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeCaseExactJks);
		m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeBks);
		m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeBksV1);
		m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeUber);
		m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeBcfks);
		m_jmChangeKeyStoreType.add(m_jmiChangeKeyStoreTypeGkr);

		// Others

		JMenuItem jmiKeyStoreReport = new JMenuItem(m_keyStoreReportAction);
		jmiKeyStoreReport.setToolTipText(null);
		jmiKeyStoreReport.addChangeListener(
		    new StatusBarChangeHandler((String) m_keyStoreReportAction.getValue(Action.LONG_DESCRIPTION), this));
		jmTools.add(jmiKeyStoreReport);

		jmTools.addSeparator();

		JMenuItem jmiOptions = new JMenuItem(RB.getString("FPortecle.jmiOptions.text"),
		    RB.getString("FPortecle.jmiOptions.mnemonic").charAt(0));
		jmiOptions.setIcon(new ImageIcon(getResImage("FPortecle.jmiOptions.image")));
		jmTools.add(jmiOptions);
		jmiOptions.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				showOptions();
			}
		});
		jmiOptions.addChangeListener(new StatusBarChangeHandler(RB.getString("FPortecle.jmiOptions.statusbar"), this));

		// Examine menu
		JMenu jmExamine = new JMenu(RB.getString("FPortecle.jmExamine.text"));
		jmExamine.setMnemonic(RB.getString("FPortecle.jmExamine.mnemonic").charAt(0));

		JMenuItem jmiExamineCert = new JMenuItem(m_examineCertAction);
		jmiExamineCert.setToolTipText(null);
		jmiExamineCert.addChangeListener(
		    new StatusBarChangeHandler((String) m_examineCertAction.getValue(Action.LONG_DESCRIPTION), this));
		jmExamine.add(jmiExamineCert);

		JMenuItem jmiExamineCertSSL = new JMenuItem(m_examineCertSSLAction);
		jmiExamineCertSSL.setToolTipText(null);
		jmiExamineCertSSL.addChangeListener(
		    new StatusBarChangeHandler((String) m_examineCertSSLAction.getValue(Action.LONG_DESCRIPTION), this));
		jmExamine.add(jmiExamineCertSSL);

		JMenuItem jmiExamineCsr = new JMenuItem(m_examineCsrAction);
		jmiExamineCsr.setToolTipText(null);
		jmiExamineCsr.addChangeListener(
		    new StatusBarChangeHandler((String) m_examineCsrAction.getValue(Action.LONG_DESCRIPTION), this));
		jmExamine.add(jmiExamineCsr);

		JMenuItem jmiExamineCrl = new JMenuItem(m_examineCrlAction);
		jmiExamineCrl.setToolTipText(null);
		jmiExamineCrl.addChangeListener(
		    new StatusBarChangeHandler((String) m_examineCrlAction.getValue(Action.LONG_DESCRIPTION), this));
		jmExamine.add(jmiExamineCrl);

		// Help menu
		JMenu jmHelp = new JMenu(RB.getString("FPortecle.jmHelp.text"));
		jmHelp.setMnemonic(RB.getString("FPortecle.jmHelp.mnemonic").charAt(0));

		JMenuItem jmiHelp = new JMenuItem(m_helpAction);
		jmiHelp.setToolTipText(null);
		jmiHelp.addChangeListener(
		    new StatusBarChangeHandler((String) m_helpAction.getValue(Action.LONG_DESCRIPTION), this));
		jmHelp.add(jmiHelp);

		// Online Resources menu (sub-menu of Help)
		JMenu jmOnlineResources = new JMenu(RB.getString("FPortecle.jmOnlineResources.text"));
		jmOnlineResources.setIcon(new ImageIcon(getResImage("FPortecle.jmOnlineResources.image")));
		jmOnlineResources.setMnemonic(RB.getString("FPortecle.jmOnlineResources.mnemonic").charAt(0));
		jmHelp.add(jmOnlineResources);

		JMenuItem jmiWebsite = new JMenuItem(RB.getString("FPortecle.jmiWebsite.text"),
		    RB.getString("FPortecle.jmiWebsite.mnemonic").charAt(0));
		jmiWebsite.setIcon(new ImageIcon(getResImage("FPortecle.jmiWebsite.image")));
		jmOnlineResources.add(jmiWebsite);
		jmiWebsite.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				visitWebsite();
			}
		});
		jmiWebsite.addChangeListener(new StatusBarChangeHandler(RB.getString("FPortecle.jmiWebsite.statusbar"), this));

		JMenuItem jmiSFNetProject = new JMenuItem(RB.getString("FPortecle.jmiSFNetProject.text"),
		    RB.getString("FPortecle.jmiSFNetProject.mnemonic").charAt(0));
		jmiSFNetProject.setIcon(new ImageIcon(getResImage("FPortecle.jmiSFNetProject.image")));
		jmOnlineResources.add(jmiSFNetProject);
		jmiSFNetProject.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				visitSFNetProject();
			}
		});
		jmiSFNetProject.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.jmiSFNetProject.statusbar"), this));

		/*
		 * Update check disabled for now... JMenuItem jmiCheckUpdate = new JMenuItem(
		 * m_res.getString("FPortecle.jmiCheckUpdate.text"),
		 * m_res.getString("FPortecle.jmiCheckUpdate.mnemonic").charAt(0)); jmiCheckUpdate.setIcon( new
		 * ImageIcon(getResImage("FPortecle.jmiCheckUpdate.image"))); jmOnlineResources.add(jmiCheckUpdate);
		 * jmiCheckUpdate.addActionListener(new ActionListener() { protected void act() { checkForUpdate(); }}); new
		 * StatusBarChangeHandler( jmiCheckUpdate, m_res.getString("FPortecle.jmiCheckUpdate.statusbar"), this);
		 */

		JMenuItem jmiDonate = new JMenuItem(RB.getString("FPortecle.jmiDonate.text"),
		    RB.getString("FPortecle.jmiDonate.mnemonic").charAt(0));
		jmiDonate.setIcon(new ImageIcon(getResImage("FPortecle.jmiDonate.image")));
		jmiDonate.setToolTipText(null);
		jmOnlineResources.add(jmiDonate);
		jmiDonate.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				makeDonation();
			}
		});
		jmiDonate.addChangeListener(new StatusBarChangeHandler(RB.getString("FPortecle.jmiDonate.statusbar"), this));

		jmHelp.addSeparator();

		JMenuItem jmiSecurityProviders = new JMenuItem(RB.getString("FPortecle.jmiSecurityProviders.text"),
		    RB.getString("FPortecle.jmiSecurityProviders.mnemonic").charAt(0));
		jmiSecurityProviders.setIcon(new ImageIcon(getResImage("FPortecle.jmiSecurityProviders.image")));
		jmHelp.add(jmiSecurityProviders);
		jmiSecurityProviders.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				showSecurityProviders();
			}
		});
		jmiSecurityProviders.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.jmiSecurityProviders.statusbar"), this));

		JMenuItem jmiJars =
		    new JMenuItem(RB.getString("FPortecle.jmiJars.text"), RB.getString("FPortecle.jmiJars.mnemonic").charAt(0));
		jmiJars.setIcon(new ImageIcon(getResImage("FPortecle.jmiJars.image")));
		jmHelp.add(jmiJars);
		jmiJars.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				showJarInfo();
			}
		});
		jmiJars.addChangeListener(new StatusBarChangeHandler(RB.getString("FPortecle.jmiJars.statusbar"), this));

		jmHelp.addSeparator();

		JMenuItem jmiAbout = new JMenuItem(RB.getString("FPortecle.jmiAbout.text"),
		    RB.getString("FPortecle.jmiAbout.mnemonic").charAt(0));
		jmiAbout.setIcon(new ImageIcon(getResImage("FPortecle.jmiAbout.image")));
		jmHelp.add(jmiAbout);
		jmiAbout.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				showAbout();
			}
		});
		jmiAbout.addChangeListener(new StatusBarChangeHandler(RB.getString("FPortecle.jmiAbout.statusbar"), this));

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
		jmirfNew.setIcon(new ImageIcon(getResImage("FPortecle.OpenRecent.image")));
		jmirfNew.addActionListener(new RecentKeyStoreFileActionListener(fRecentFile, this));

		jmirfNew.addChangeListener(new StatusBarChangeHandler(
		    MessageFormat.format(RB.getString("FPortecle.recentfile.statusbar"), fRecentFile), this));
		return jmirfNew;
	}

	/**
	 * Initialize FPortecle frame's tool bar GUI components.
	 */
	private void initToolBar()
	{
		// Create the "new" tool bar button
		JButton jbNewKeyStore = new JButton();
		jbNewKeyStore.setAction(m_newKeyStoreAction);
		jbNewKeyStore.setText(null); // Don't share text from action
		// Get around bug with action mnemonics on tool bar buttons
		jbNewKeyStore.setMnemonic(0);
		jbNewKeyStore.setFocusable(false);
		jbNewKeyStore.addMouseListener(new MouseAdapter()
		{
			@Override
			public void mouseEntered(MouseEvent evt)
			{
				setStatusBarText((String) m_newKeyStoreAction.getValue(Action.LONG_DESCRIPTION));
			}

			@Override
			public void mouseExited(MouseEvent evt)
			{
				setDefaultStatusBarText();
			}
		});

		// Create the "open" tool bar button
		JButton jbOpenKeyStoreFile = new JButton();
		jbOpenKeyStoreFile.setAction(m_openKeyStoreFileAction);
		jbOpenKeyStoreFile.setText(null); // Don't share text from action
		// Get around bug with action mnemonics on tool bar buttons
		jbOpenKeyStoreFile.setMnemonic(0);
		jbOpenKeyStoreFile.setFocusable(false);
		jbOpenKeyStoreFile.addMouseListener(new MouseAdapter()
		{
			@Override
			public void mouseEntered(MouseEvent evt)
			{
				setStatusBarText((String) m_openKeyStoreFileAction.getValue(Action.LONG_DESCRIPTION));
			}

			@Override
			public void mouseExited(MouseEvent evt)
			{
				setDefaultStatusBarText();
			}
		});

		// Create the "save" tool bar button
		JButton jbSaveKeyStore = new JButton();
		jbSaveKeyStore.setAction(m_saveKeyStoreAction);
		jbSaveKeyStore.setText(null); // Don't share text from action
		// Get around bug with action mnemonics on tool bar buttons
		jbSaveKeyStore.setMnemonic(0);
		jbSaveKeyStore.setFocusable(false);
		jbSaveKeyStore.addMouseListener(new MouseAdapter()
		{
			@Override
			public void mouseEntered(MouseEvent evt)
			{
				setStatusBarText((String) m_saveKeyStoreAction.getValue(Action.LONG_DESCRIPTION));
			}

			@Override
			public void mouseExited(MouseEvent evt)
			{
				setDefaultStatusBarText();
			}
		});

		// Create the "generate key pair" tool bar button
		JButton jbGenKeyPair = new JButton();
		jbGenKeyPair.setAction(m_genKeyPairAction);
		jbGenKeyPair.setText(null); // Don't share text from action
		// Get around bug with action mnemonics on tool bar buttons
		jbGenKeyPair.setMnemonic(0);
		jbGenKeyPair.setFocusable(false);
		jbGenKeyPair.addMouseListener(new MouseAdapter()
		{
			@Override
			public void mouseEntered(MouseEvent evt)
			{
				setStatusBarText((String) m_genKeyPairAction.getValue(Action.LONG_DESCRIPTION));
			}

			@Override
			public void mouseExited(MouseEvent evt)
			{
				setDefaultStatusBarText();
			}
		});

		// Create the "import trusted certificate" tool bar button
		JButton jbImportTrustCert = new JButton();
		jbImportTrustCert.setAction(m_importTrustCertAction);
		jbImportTrustCert.setText(null); // Don't share text from action
		// Get around bug with action mnemonics on tool bar buttons
		jbImportTrustCert.setMnemonic(0);
		jbImportTrustCert.setFocusable(false);
		jbImportTrustCert.addMouseListener(new MouseAdapter()
		{
			@Override
			public void mouseEntered(MouseEvent evt)
			{
				setStatusBarText((String) m_importTrustCertAction.getValue(Action.LONG_DESCRIPTION));
			}

			@Override
			public void mouseExited(MouseEvent evt)
			{
				setDefaultStatusBarText();
			}
		});

		// Create the "import key pair" tool bar button
		JButton jbImportKeyPair = new JButton();
		jbImportKeyPair.setAction(m_importKeyPairAction);
		jbImportKeyPair.setText(null); // Don't share text from action
		// Get around bug with action mnemonics on tool bar buttons
		jbImportKeyPair.setMnemonic(0);
		jbImportKeyPair.setFocusable(false);
		jbImportKeyPair.addMouseListener(new MouseAdapter()
		{
			@Override
			public void mouseEntered(MouseEvent evt)
			{
				setStatusBarText((String) m_importKeyPairAction.getValue(Action.LONG_DESCRIPTION));
			}

			@Override
			public void mouseExited(MouseEvent evt)
			{
				setDefaultStatusBarText();
			}
		});

		// Create the "set keystore password" tool bar button
		JButton jbSetKeyStorePass = new JButton();
		jbSetKeyStorePass.setAction(m_setKeyStorePassAction);
		jbSetKeyStorePass.setText(null); // Don't share text from action
		// Get around bug with action mnemonics on tool bar buttons
		jbSetKeyStorePass.setMnemonic(0);
		jbSetKeyStorePass.setFocusable(false);
		jbSetKeyStorePass.addMouseListener(new MouseAdapter()
		{
			@Override
			public void mouseEntered(MouseEvent evt)
			{
				setStatusBarText((String) m_setKeyStorePassAction.getValue(Action.LONG_DESCRIPTION));
			}

			@Override
			public void mouseExited(MouseEvent evt)
			{
				setDefaultStatusBarText();
			}
		});

		// Create the "keystore report" tool bar button
		JButton jbKeyStoreReport = new JButton();
		jbKeyStoreReport.setAction(m_keyStoreReportAction);
		jbKeyStoreReport.setText(null); // Don't share text from action
		// Get around bug with action mnemonics on tool bar buttons
		jbKeyStoreReport.setMnemonic(0);
		jbKeyStoreReport.setFocusable(false);
		jbKeyStoreReport.addMouseListener(new MouseAdapter()
		{
			@Override
			public void mouseEntered(MouseEvent evt)
			{
				setStatusBarText((String) m_keyStoreReportAction.getValue(Action.LONG_DESCRIPTION));
			}

			@Override
			public void mouseExited(MouseEvent evt)
			{
				setDefaultStatusBarText();
			}
		});

		// Create the "examine certificate" tool bar button
		JButton jbExamineCert = new JButton();
		jbExamineCert.setAction(m_examineCertAction);
		jbExamineCert.setText(null); // Don't share text from action
		// Get around bug with action mnemonics on tool bar buttons
		jbExamineCert.setMnemonic(0);
		jbExamineCert.setFocusable(false);
		jbExamineCert.addMouseListener(new MouseAdapter()
		{
			@Override
			public void mouseEntered(MouseEvent evt)
			{
				setStatusBarText((String) m_examineCertAction.getValue(Action.LONG_DESCRIPTION));
			}

			@Override
			public void mouseExited(MouseEvent evt)
			{
				setDefaultStatusBarText();
			}
		});

		// Create the "examine CRL" tool bar button
		JButton jbExamineCrl = new JButton();
		jbExamineCrl.setAction(m_examineCrlAction);
		jbExamineCrl.setText(null); // Don't share text from action
		// Get around bug with action mnemonics on tool bar buttons
		jbExamineCrl.setMnemonic(0);
		jbExamineCrl.setFocusable(false);
		jbExamineCrl.addMouseListener(new MouseAdapter()
		{
			@Override
			public void mouseEntered(MouseEvent evt)
			{
				setStatusBarText((String) m_examineCrlAction.getValue(Action.LONG_DESCRIPTION));
			}

			@Override
			public void mouseExited(MouseEvent evt)
			{
				setDefaultStatusBarText();
			}
		});

		// Create the "help" tool bar button
		JButton jbHelp = new JButton();
		jbHelp.setAction(m_helpAction);
		jbHelp.setText(null); // Don't share text from action
		// Get around bug with action mnemonics on tool bar buttons
		jbHelp.setMnemonic(0);
		jbHelp.setFocusable(false);
		jbHelp.addMouseListener(new MouseAdapter()
		{
			@Override
			public void mouseEntered(MouseEvent evt)
			{
				setStatusBarText((String) m_helpAction.getValue(Action.LONG_DESCRIPTION));
			}

			@Override
			public void mouseExited(MouseEvent evt)
			{
				setDefaultStatusBarText();
			}
		});

		// The tool bar
		JToolBar jtbToolBar = new JToolBar();
		jtbToolBar.setFloatable(false);
		jtbToolBar.setRollover(true);
		jtbToolBar.setName(RB.getString("FPortecle.jtbToolBar.name"));

		// Add the buttons to the tool bar - use visible separators for all L&Fs
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

		// Add the tool bar to the frame
		getContentPane().add(jtbToolBar, BorderLayout.NORTH);
	}

	/**
	 * Initialize FPortecle frame's keystore content table GUI components.
	 */
	private void initTable()
	{
		// The table data model
		KeyStoreTableModel ksModel = new KeyStoreTableModel(this);

		// The table itself
		m_jtKeyStore = new KeyStoreTable(ksModel);

		m_jtKeyStore.setShowGrid(false);
		m_jtKeyStore.setRowMargin(0);
		m_jtKeyStore.getColumnModel().setColumnMargin(0);
		m_jtKeyStore.getTableHeader().setReorderingAllowed(false);
		m_jtKeyStore.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
		// Top accommodate entry icons with spare space (16 pixels tall)
		m_jtKeyStore.setRowHeight(18);

		// Add custom renderers for the table headers and cells
		for (int iCnt = 0; iCnt < m_jtKeyStore.getColumnCount(); iCnt++)
		{
			TableColumn column = m_jtKeyStore.getColumnModel().getColumn(iCnt);
			column.setHeaderRenderer(new KeyStoreTableHeadRend());
			column.setCellRenderer(new KeyStoreTableCellRend());
		}

		// Make the first column small and not resizable (it holds icons to represent the different entry
		// types)
		TableColumn typeCol = m_jtKeyStore.getColumnModel().getColumn(0);
		typeCol.setResizable(false);
		typeCol.setMinWidth(20);
		typeCol.setMaxWidth(20);
		typeCol.setPreferredWidth(20);

		// Set alias columns width according to the relevant application property unless the property is not
		// present or is invalid.
		int iAliasWidth = PREFS.getInt(RB.getString("AppPrefs.AliasWidth"), 0);

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

		// Make the table sortable
		m_jtKeyStore.setAutoCreateRowSorter(true);
		// ...and sort it by alias by default
		m_jtKeyStore.getRowSorter().toggleSortOrder(1);

		// Get usual double click edit start out of the way - we want double click to show the
		// entry, even in editable columns. In-place edit can be invoked with F2.
		TableCellEditor cellEditor = m_jtKeyStore.getDefaultEditor(String.class);
		if (cellEditor instanceof DefaultCellEditor)
		{
			((DefaultCellEditor) cellEditor).setClickCountToStart(1000);
		}

		// Put the table into a scroll pane
		JScrollPane jspKeyStoreTable = new JScrollPane(m_jtKeyStore, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
		    ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		jspKeyStoreTable.getViewport().setBackground(m_jtKeyStore.getBackground());

		// Get the size of the keystore table panel from the application preferences
		int iWidth = PREFS.getInt(RB.getString("AppPrefs.TableWidth"), 0);
		int iHeight = PREFS.getInt(RB.getString("AppPrefs.TableHeight"), 0);

		// Put the scroll pane into a panel. The preferred size of the panel dictates the size of the entire
		// frame
		m_jpKeyStoreTable = new JPanel(new BorderLayout(10, 10));

		if (iWidth <= 0 || iHeight <= 0)
		{
			m_jpKeyStoreTable.setPreferredSize(new Dimension(DEFAULT_TABLE_WIDTH, DEFAULT_TABLE_HEIGHT));
		}
		else
		{
			m_jpKeyStoreTable.setPreferredSize(new Dimension(iWidth, iHeight));
		}

		m_jpKeyStoreTable.add(jspKeyStoreTable, BorderLayout.CENTER);
		m_jpKeyStoreTable.setBorder(new EmptyBorder(3, 3, 3, 3));

		// Add mouse listeners to show pop-up menus when table entries are clicked upon; maybeShowPopup for
		// both mousePressed and mouseReleased for cross-platform compatibility. Also add listeners to show an
		// entry's certificate details if it is double-clicked
		m_jtKeyStore.addMouseListener(new MouseAdapter()
		{
			@Override
			public void mouseClicked(MouseEvent evt)
			{
				keyStoreTableDoubleClick(evt);
			}

			@Override
			public void mousePressed(MouseEvent evt)
			{
				maybeShowPopup(evt);
			}

			@Override
			public void mouseReleased(MouseEvent evt)
			{
				maybeShowPopup(evt);
			}
		});
		m_jpKeyStoreTable.setTransferHandler(m_jtKeyStore.getTransferHandler());
		getContentPane().add(m_jpKeyStoreTable, BorderLayout.CENTER);
	}

	/**
	 * Initialize FPortecle frame's status bar GUI components.
	 */
	private void initStatusBar()
	{
		m_jlStatusBar = new JLabel();

		m_jlStatusBar.setBorder(new CompoundBorder(new EmptyBorder(3, 3, 3, 3),
		    new CompoundBorder(new BevelBorder(BevelBorder.LOWERED), new EmptyBorder(0, 2, 0, 2))));
		setDefaultStatusBarText();

		getContentPane().add(m_jlStatusBar, BorderLayout.SOUTH);
	}

	/**
	 * Initialize FPortecle frame's pop-up menu GUI components. These are invoked when rows of specific types are
	 * clicked upon in the keystore table.
	 */
	private void initPopupMenus()
	{
		// Initialize key-only entry pop-up menu including mnemonics and listeners
		m_jpmKey = new JPopupMenu();

		JMenuItem jmiKeyDelete = new JMenuItem(RB.getString("FPortecle.jmiKeyDelete.text"),
		    RB.getString("FPortecle.jmiKeyDelete.mnemonic").charAt(0));
		jmiKeyDelete.setIcon(new ImageIcon(getResImage("FPortecle.jmiKeyDelete.image")));
		jmiKeyDelete.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				deleteSelectedEntry();
			}
		});
		jmiKeyDelete.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.jmiKeyDelete.statusbar"), this));

		m_jpmKey.add(jmiKeyDelete);

		// Initialize key pair entry pop-up menu including mnemonics and listeners
		m_jpmKeyPair = new JPopupMenu();

		JMenuItem jmiKeyPairCertDetails = new JMenuItem(RB.getString("FPortecle.jmiKeyPairCertDetails.text"),
		    RB.getString("FPortecle.jmiKeyPairCertDetails.mnemonic").charAt(0));
		jmiKeyPairCertDetails.setIcon(new ImageIcon(getResImage("FPortecle.jmiKeyPairCertDetails.image")));
		jmiKeyPairCertDetails.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				showSelectedEntry();
			}
		});
		jmiKeyPairCertDetails.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.jmiKeyPairCertDetails.statusbar"), this));

		JMenuItem jmiKeyPairExport = new JMenuItem(RB.getString("FPortecle.jmiKeyPairExport.text"),
		    RB.getString("FPortecle.jmiKeyPairExport.mnemonic").charAt(0));
		jmiKeyPairExport.setIcon(new ImageIcon(getResImage("FPortecle.jmiKeyPairExport.image")));

		jmiKeyPairExport.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				exportSelectedEntry();
			}
		});
		jmiKeyPairExport.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.jmiKeyPairExport.statusbar"), this));

		JMenuItem jmiGenerateCSR = new JMenuItem(RB.getString("FPortecle.jmiGenerateCSR.text"),
		    RB.getString("FPortecle.jmiGenerateCSR.mnemonic").charAt(0));
		jmiGenerateCSR.setIcon(new ImageIcon(getResImage("FPortecle.jmiGenerateCSR.image")));
		jmiGenerateCSR.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				generateCsrSelectedEntry();
			}
		});
		jmiGenerateCSR.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.jmiGenerateCSR.statusbar"), this));

		JMenuItem jmiImportCAReply = new JMenuItem(RB.getString("FPortecle.jmiImportCAReply.text"),
		    RB.getString("FPortecle.jmiImportCAReply.mnemonic").charAt(0));
		jmiImportCAReply.setIcon(new ImageIcon(getResImage("FPortecle.jmiImportCAReply.image")));
		jmiImportCAReply.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				importCAReplySelectedEntry();
			}
		});
		jmiImportCAReply.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.jmiImportCAReply.statusbar"), this));

		JMenuItem jmiRenew = new JMenuItem(RB.getString("FPortecle.jmiRenew.text"),
		    RB.getString("FPortecle.jmiRenew.mnemonic").charAt(0));
		jmiRenew.setIcon(new ImageIcon(getResImage("FPortecle.jmiRenew.image")));
		jmiRenew.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				renewSelectedEntry();
			}
		});
		jmiRenew.addChangeListener(new StatusBarChangeHandler(RB.getString("FPortecle.jmiRenew.statusbar"), this));

		m_jmiSetKeyPairPass = new JMenuItem(RB.getString("FPortecle.m_jmiSetKeyPairPass.text"),
		    RB.getString("FPortecle.m_jmiSetKeyPairPass.mnemonic").charAt(0));
		m_jmiSetKeyPairPass.setIcon(new ImageIcon(getResImage("FPortecle.m_jmiSetKeyPairPass.image")));
		m_jmiSetKeyPairPass.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				setPasswordSelectedEntry();
			}
		});
		m_jmiSetKeyPairPass.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.m_jmiSetKeyPairPass.statusbar"), this));

		JMenuItem jmiKeyPairDelete = new JMenuItem(RB.getString("FPortecle.jmiKeyPairDelete.text"),
		    RB.getString("FPortecle.jmiKeyPairDelete.mnemonic").charAt(0));
		jmiKeyPairDelete.setIcon(new ImageIcon(getResImage("FPortecle.jmiKeyPairDelete.image")));
		jmiKeyPairDelete.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				deleteSelectedEntry();
			}
		});
		jmiKeyPairDelete.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.jmiKeyPairDelete.statusbar"), this));

		JMenuItem jmiKeyPairClone = new JMenuItem(RB.getString("FPortecle.jmiKeyPairClone.text"),
		    RB.getString("FPortecle.jmiKeyPairClone.mnemonic").charAt(0));
		jmiKeyPairClone.setIcon(new ImageIcon(getResImage("FPortecle.jmiKeyPairClone.image")));
		jmiKeyPairClone.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				cloneSelectedKeyEntry();
			}
		});
		jmiKeyPairClone.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.jmiKeyPairClone.statusbar"), this));

		JMenuItem jmiKeyPairRename = new JMenuItem(RB.getString("FPortecle.jmiKeyPairRename.text"),
		    RB.getString("FPortecle.jmiKeyPairRename.mnemonic").charAt(0));
		jmiKeyPairRename.setIcon(new ImageIcon(getResImage("FPortecle.jmiKeyPairRename.image")));
		jmiKeyPairRename.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				renameSelectedEntry();
			}
		});
		jmiKeyPairRename.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.jmiKeyPairRename.statusbar"), this));

		m_jpmKeyPair.add(jmiKeyPairCertDetails);
		m_jpmKeyPair.addSeparator();
		m_jpmKeyPair.add(jmiKeyPairExport);
		m_jpmKeyPair.add(jmiGenerateCSR);
		m_jpmKeyPair.add(jmiImportCAReply);
		if (EXPERIMENTAL)
		{
			// TODO: should show this for self-signed key pair certificates only
			m_jpmKeyPair.add(jmiRenew);
		}
		m_jpmKeyPair.addSeparator();
		m_jpmKeyPair.add(m_jmiSetKeyPairPass);
		m_jpmKeyPair.add(jmiKeyPairDelete);
		m_jpmKeyPair.add(jmiKeyPairClone);
		m_jpmKeyPair.add(jmiKeyPairRename);

		// Initialize Trusted Certificate entry pop-up menu including mnemonics and listeners
		m_jpmCert = new JPopupMenu();

		JMenuItem jmiTrustCertDetails = new JMenuItem(RB.getString("FPortecle.jmiTrustCertDetails.text"),
		    RB.getString("FPortecle.jmiTrustCertDetails.mnemonic").charAt(0));
		jmiTrustCertDetails.setIcon(new ImageIcon(getResImage("FPortecle.jmiTrustCertDetails.image")));
		jmiTrustCertDetails.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				showSelectedEntry();
			}
		});
		jmiTrustCertDetails.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.jmiTrustCertDetails.statusbar"), this));

		JMenuItem jmiTrustCertExport = new JMenuItem(RB.getString("FPortecle.jmiTrustCertExport.text"),
		    RB.getString("FPortecle.jmiTrustCertExport.mnemonic").charAt(0));
		jmiTrustCertExport.setIcon(new ImageIcon(getResImage("FPortecle.jmiTrustCertExport.image")));
		jmiTrustCertExport.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				exportSelectedEntry();
			}
		});
		jmiTrustCertExport.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.jmiTrustCertExport.statusbar"), this));

		JMenuItem jmiTrustCertDelete = new JMenuItem(RB.getString("FPortecle.jmiTrustCertDelete.text"),
		    RB.getString("FPortecle.jmiTrustCertDelete.mnemonic").charAt(0));
		jmiTrustCertDelete.setIcon(new ImageIcon(getResImage("FPortecle.jmiTrustCertDelete.image")));
		jmiTrustCertDelete.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				deleteSelectedEntry();
			}
		});
		jmiTrustCertDelete.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.jmiTrustCertDelete.statusbar"), this));

		JMenuItem jmiTrustCertClone = new JMenuItem(RB.getString("FPortecle.jmiTrustCertClone.text"),
		    RB.getString("FPortecle.jmiTrustCertClone.mnemonic").charAt(0));
		jmiTrustCertClone.setIcon(new ImageIcon(getResImage("FPortecle.jmiTrustCertClone.image")));
		jmiTrustCertClone.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				cloneSelectedCertificateEntry();
			}
		});
		jmiTrustCertClone.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.jmiTrustCertClone.statusbar"), this));

		JMenuItem jmiTrustCertRename = new JMenuItem(RB.getString("FPortecle.jmiTrustCertRename.text"),
		    RB.getString("FPortecle.jmiTrustCertRename.mnemonic").charAt(0));
		jmiTrustCertRename.setIcon(new ImageIcon(getResImage("FPortecle.jmiTrustCertRename.image")));
		jmiTrustCertRename.addActionListener(new ActionListener()
		{
			@Override
			protected void act()
			{
				renameSelectedEntry();
			}
		});
		jmiTrustCertRename.addChangeListener(
		    new StatusBarChangeHandler(RB.getString("FPortecle.jmiTrustCertRename.statusbar"), this));

		m_jpmCert.add(jmiTrustCertDetails);
		m_jpmCert.addSeparator();
		m_jpmCert.add(jmiTrustCertExport);
		m_jpmCert.addSeparator();
		m_jpmCert.add(jmiTrustCertDelete);
		m_jpmCert.add(jmiTrustCertClone);
		m_jpmCert.add(jmiTrustCertRename);
	}

	/**
	 * Show the appropriate pop-up menu if the originating mouse event indicates that the user clicked upon a keystore
	 * entry in the UI table and the entry is of type key pair or trusted certificate.
	 *
	 * @param evt The mouse event
	 */
	private void maybeShowPopup(MouseEvent evt)
	{
		if (evt.isPopupTrigger())
		{
			// What row was clicked upon (if any)?
			Point point = new Point(evt.getX(), evt.getY());
			int iRow = m_jtKeyStore.rowAtPoint(point);

			if (iRow != -1)
			{
				// Make the row that was clicked upon the selected one
				m_jtKeyStore.setRowSelectionInterval(iRow, iRow);

				// Show one menu if the keystore entry is of type key pair...
				String currEntry = m_jtKeyStore.getSelectedType();
				if (currEntry.equals(KeyStoreTableModel.KEY_PAIR_ENTRY))
				{
					m_jpmKeyPair.show(evt.getComponent(), evt.getX(), evt.getY());
				}
				// ...and another if the type is trusted certificate
				else if (currEntry.equals(KeyStoreTableModel.TRUST_CERT_ENTRY))
				{
					m_jpmCert.show(evt.getComponent(), evt.getX(), evt.getY());
				}
				// ...and yet another for key-only entries
				else if (currEntry.equals(KeyStoreTableModel.KEY_ENTRY))
				{
					m_jpmKey.show(evt.getComponent(), evt.getX(), evt.getY());
				}
				// What's this?
				else
				{
					LOG.warning("Popup context menu requested for unknown entry: " + currEntry);
				}
			}
		}
	}

	/**
	 * Check if a double click occurred on the keystore table. If it has show the certificate details of the entry
	 * clicked upon.
	 *
	 * @param evt The mouse event
	 */
	private void keyStoreTableDoubleClick(MouseEvent evt)
	{
		if (evt.getClickCount() > 1)
		{
			// Due to the way click events work, at this point we've already received a previous single click
			// event which has selected a row for us and we can just show the selected entry.
			showSelectedEntry();
		}
	}

	/**
	 * Display the about dialog.
	 */
	private void showAbout()
	{
		// Display About Dialog in the centre of the frame
		DAbout dAbout = new DAbout(this);
		dAbout.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dAbout);
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

		// Display the Generate Key Pair dialog to get the key pair generation parameters from the user
		DGenerateKeyPair dGenerateKeyPair = new DGenerateKeyPair(this);
		dGenerateKeyPair.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dGenerateKeyPair);

		if (!dGenerateKeyPair.isSuccessful())
		{
			return false; // User canceled the dialog
		}

		int iKeySize = dGenerateKeyPair.getKeySize();
		KeyPairType keyPairType = dGenerateKeyPair.getKeyPairType();
		DGeneratingKeyPair dGeneratingKeyPair = new DGeneratingKeyPair(this);

		// Start key pair generation in background thread
		SwingWorker<KeyPair, Object> worker = dGeneratingKeyPair.getKeyPairWorker(keyPairType, iKeySize);
		worker.execute();

		// While the key pair is being generated, ask user for certificate date
		DGenerateCertificate dGenerateCertificate =
		    new DGenerateCertificate(this, RB.getString("FPortecle.GenerateCertificate.Title"), keyPairType);
		dGenerateCertificate.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dGenerateCertificate);

		if (!dGenerateCertificate.isSuccessful())
		{
			// User canceled the dialog. Ideally we'd like to kill the background key pair generation task
			// here, but unfortunately cancel(true) doesn't do it. Any sane ways to accomplish that?
			worker.cancel(true);
			return false;
		}

		if (!worker.isDone())
		{
			// Show "progress" dialog
			dGeneratingKeyPair.setLocationRelativeTo(this);
			SwingHelper.showAndWait(dGeneratingKeyPair);

			if (!dGeneratingKeyPair.isClosedByWorker())
			{
				// User canceled the dialog. Ideally we'd like to kill the background key pair generation task
				// here, but unfortunately cancel(true) doesn't do it. Any sane ways to accomplish that?
				worker.cancel(true);
				return false;
			}
		}

		KeyPair keyPair;
		try
		{
			keyPair = worker.get();
		}
		catch (InterruptedException e)
		{
			return false;
		}
		catch (ExecutionException e)
		{
			Throwable cause = e.getCause();
			DThrowable.showAndWait(this, null, cause == null ? e : cause);
			return false;
		}

		X509Certificate certificate = dGenerateCertificate.generateCertificate(keyPair);
		if (certificate == null)
		{
			return false; // user canceled dialog or an error occurred
		}

		// Get the keystore
		KeyStore keyStore = m_keyStoreWrap.getKeyStore();

		// Get an alias for the new keystore entry
		String sAlias = X509CertUtil.getCertificateAlias(certificate).toLowerCase();
		try
		{
			sAlias = getNewEntryAlias(keyStore, sAlias, "DGenerateCertificate.KeyPairEntryAlias.Title", false);
		}
		catch (KeyStoreException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}
		if (sAlias == null)
		{
			return false;
		}

		// Get a password for the new keystore entry if applicable
		char[] cPassword = KeyStoreUtil.DUMMY_PASSWORD;

		if (m_keyStoreWrap.getKeyStoreType().isEntryPasswordSupported())
		{
			DGetNewPassword dGetNewPassword =
			    new DGetNewPassword(this, RB.getString("DGenerateCertificate.KeyPairEntryPassword.Title"));
			dGetNewPassword.setLocationRelativeTo(this);
			SwingHelper.showAndWait(dGetNewPassword);
			cPassword = dGetNewPassword.getPassword();

			if (cPassword == null)
			{
				return false;
			}
		}

		// Place the private key and certificate into the keystore and update the keystore wrapper
		try
		{
			// Delete old entry first
			if (keyStore.containsAlias(sAlias))
			{
				keyStore.deleteEntry(sAlias);
			}

			// Store the new one
			keyStore.setKeyEntry(sAlias, keyPair.getPrivate(), cPassword, new X509Certificate[] { certificate });
			m_keyStoreWrap.setEntryPassword(sAlias, cPassword);
			m_keyStoreWrap.setChanged(true);
		}
		catch (KeyStoreException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}

		// Update the frame's components and title
		selectedAlias = sAlias;
		updateControls();
		updateTitle();

		// Display success message
		JOptionPane.showMessageDialog(this, RB.getString("FPortecle.KeyPairGenerationSuccessful.message"),
		    RB.getString("FPortecle.GenerateCertificate.Title"), JOptionPane.INFORMATION_MESSAGE);
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
		if (needSave())
		{
			// Yes - ask the user if it should be saved
			int iWantSave = wantSave();

			if ((iWantSave == JOptionPane.YES_OPTION && !saveKeyStore()) || iWantSave == JOptionPane.CANCEL_OPTION)
			{
				return false;
			}
		}

		// Let the user choose a file to open from
		JFileChooser chooser = FileChooserFactory.getKeyStoreFileChooser(null);

		File fLastDir = m_lastDir.getLastDir();
		if (fLastDir != null)
		{
			chooser.setCurrentDirectory(fLastDir);
		}

		chooser.setDialogTitle(RB.getString("FPortecle.OpenKeyStoreFile.Title"));
		chooser.setMultiSelectionEnabled(false);

		int iRtnValue = chooser.showOpenDialog(this);
		if (iRtnValue == JFileChooser.APPROVE_OPTION)
		{
			File fOpenFile = chooser.getSelectedFile();

			// File chosen - open the keystore
			if (openKeyStoreFile(fOpenFile, true))
			{
				return true;
			}
		}
		return false;
	}

	/**
	 * Open a CA certificates keystore file from disk.
	 *
	 * @return True if a keystore is opened, false otherwise
	 */
	private boolean openCaCertsKeyStoreFile()
	{
		// Does the current keystore contain unsaved changes?
		if (needSave())
		{
			// Yes - ask the user if it should be saved
			int iWantSave = wantSave();

			if ((iWantSave == JOptionPane.YES_OPTION && !saveKeyStore()) || iWantSave == JOptionPane.CANCEL_OPTION)
			{
				return false;
			}
		}

		return openKeyStoreFile(m_fCaCertsFile, false);
	}

	/**
	 * Open the supplied keystore file from disk.
	 *
	 * @param fKeyStore The keystore file
	 * @param updateLastDir Whether to update the last accessed directory
	 * @return True if a keystore is opened, false otherwise
	 */
	/* package private */boolean openKeyStoreFile(File fKeyStore, boolean updateLastDir)
	{
		// The keystore does not exist
		if (!fKeyStore.exists())
		{
			JOptionPane.showMessageDialog(this,
			    MessageFormat.format(RB.getString("FPortecle.FileNotFound.message"), fKeyStore),
			    RB.getString("FPortecle.OpenKeyStoreFile.Title"), JOptionPane.WARNING_MESSAGE);
			return false;
		}
		// The keystore file is not a file
		else if (!fKeyStore.isFile())
		{
			JOptionPane.showMessageDialog(this,
			    MessageFormat.format(RB.getString("FPortecle.NotFile.message"), fKeyStore),
			    RB.getString("FPortecle.OpenKeyStoreFile.Title"), JOptionPane.WARNING_MESSAGE);
			return false;
		}

		// Update last accessed directory
		if (updateLastDir)
		{
			m_lastDir.updateLastDir(fKeyStore);
		}

		// Get the user to enter the keystore's password
		DGetPassword dGetPassword = new DGetPassword(this,
		    MessageFormat.format(RB.getString("FPortecle.GetKeyStorePassword.Title"), fKeyStore.getName()));
		dGetPassword.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dGetPassword);
		char[] cPassword = dGetPassword.getPassword();

		if (cPassword == null)
		{
			return false;
		}

		try
		{
			// Load the keystore - try to open as each of the allowed types in turn until successful
			KeyStore openedKeyStore = null;

			// Types
			KeyStoreType[] keyStoreTypes = KeyStoreUtil.getAvailableTypes();

			// Exceptions
			CryptoException[] cexs = new CryptoException[keyStoreTypes.length];

			// Tried types
			StringBuilder tried = new StringBuilder();

			for (int iCnt = 0; iCnt < keyStoreTypes.length; iCnt++)
			{
				tried.append(", ").append(keyStoreTypes[iCnt]);
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
				if (tried.length() > 2)
				{
					tried.delete(0, 2); // Chop leading ", "
				}
				int iSelected = SwingHelper.showConfirmDialog(this,
				    MessageFormat.format(RB.getString("FPortecle.NoOpenKeyStoreFile.message"), fKeyStore, tried),
				    RB.getString("FPortecle.OpenKeyStoreFile.Title"));
				if (iSelected == JOptionPane.YES_OPTION)
				{
					for (CryptoException cex : cexs)
					{
						DThrowable.showAndWait(this, null, cex);
					}
				}

				return false;
			}

			// Create a keystore wrapper for the keystore
			m_keyStoreWrap = new KeyStoreWrapper(openedKeyStore, fKeyStore, cPassword);

			// Update the frame's components and title
			selectedAlias = null;
			updateControls();
			updateTitle();

			// Add keystore file to recent files in file menu
			m_jmrfFile.add(createRecentFileMenuItem(fKeyStore));

			return true;
		}
		catch (FileNotFoundException ex)
		{
			JOptionPane.showMessageDialog(this,
			    MessageFormat.format(RB.getString("FPortecle.NoRead.message"), fKeyStore),
			    RB.getString("FPortecle.OpenKeyStoreFile.Title"), JOptionPane.WARNING_MESSAGE);
			return false;
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
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
		if (needSave())
		{
			// Yes - ask the user if it should be saved
			int iWantSave = wantSave();

			if ((iWantSave == JOptionPane.YES_OPTION && !saveKeyStore()) || iWantSave == JOptionPane.CANCEL_OPTION)
			{
				return false;
			}
		}

		DChoosePkcs11Provider chooser =
		    new DChoosePkcs11Provider(this, RB.getString("FPortecle.ChoosePkcs11Provider.Title"), null);
		chooser.setLocationRelativeTo(this);
		SwingHelper.showAndWait(chooser);

		String provider = chooser.getProvider();
		return provider != null && openKeyStorePkcs11(provider);
	}

	/**
	 * Open the supplied PKCS #11 keystore.
	 *
	 * @param sPkcs11Provider The PKCS #11 provider
	 * @return True if a keystore is opened, false otherwise
	 */
	private boolean openKeyStorePkcs11(String sPkcs11Provider)
	{
		// Get the user to enter the keystore's password
		DGetPassword dGetPassword = new DGetPassword(this,
		    MessageFormat.format(RB.getString("FPortecle.GetKeyStorePassword.Title"), sPkcs11Provider));
		dGetPassword.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dGetPassword);
		char[] cPassword = dGetPassword.getPassword();

		if (cPassword == null)
		{
			return false;
		}

		// Load the keystore
		try
		{
			KeyStore openedKeyStore = KeyStoreUtil.loadKeyStore(sPkcs11Provider, cPassword);
			m_keyStoreWrap = new KeyStoreWrapper(openedKeyStore, null, cPassword);
		}
		catch (CryptoException e)
		{
			int iSelected = JOptionPane.showConfirmDialog(this,
			    MessageFormat.format(RB.getString("FPortecle.NoOpenKeyStorePkcs11.message"), sPkcs11Provider),
			    RB.getString("FPortecle.ChoosePkcs11Provider.Title"), JOptionPane.YES_NO_OPTION);
			if (iSelected == JOptionPane.YES_OPTION)
			{
				DThrowable.showAndWait(this, null, e);
			}
			return false;
		}

		// Update the frame's components and title
		selectedAlias = null;
		updateControls();
		updateTitle();

		return true;
	}

	/**
	 * Save the currently opened keystore back to the file it was originally opened from.
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
		if (fSaveFile == null)
		{
			return saveKeyStoreAs();
		}

		// Get the password to protect the keystore with
		char[] cPassword = m_keyStoreWrap.getPassword();

		// No password set for keystore - get one from the user
		if (cPassword == null)
		{
			cPassword = getNewKeyStorePassword();

			// User canceled - cancel save
			if (cPassword == null)
			{
				return false;
			}
		}

		try
		{
			// Do the save
			m_keyStoreWrap.setKeyStore(KeyStoreUtil.saveKeyStore(m_keyStoreWrap.getKeyStore(), fSaveFile, cPassword));

			// Update the keystore wrapper
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
			JOptionPane.showMessageDialog(this,
			    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fSaveFile),
			    RB.getString("FPortecle.SaveKeyStore.Title"), JOptionPane.WARNING_MESSAGE);
			return false;
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
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
		DGetNewPassword dGetNewPassword =
		    new DGetNewPassword(this, RB.getString("FPortecle.SetKeyStorePassword.Title"));
		dGetNewPassword.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dGetNewPassword);

		// Dialog returned - retrieve the password and return it
		return dGetNewPassword.getPassword();
	}

	/**
	 * Save the currently opened keystore to disk to what may be a different file from the one it was opened from (if
	 * any).
	 *
	 * @return True if the keystore is saved to disk, false otherwise
	 */
	private boolean saveKeyStoreAs()
	{
		assert m_keyStoreWrap != null;
		assert m_keyStoreWrap.getKeyStore() != null;

		// Keystore's current password
		char[] cPassword = m_keyStoreWrap.getPassword();

		// Get a new password if this keystore exists in another file or is an unsaved keystore for which no
		// password has been set yet
		if (m_keyStoreWrap.getKeyStoreFile() != null || (m_keyStoreWrap.getKeyStoreFile() == null && cPassword == null))
		{
			cPassword = getNewKeyStorePassword();

			if (cPassword == null)
			{
				return false;
			}
		}

		// Let the user choose a save file
		JFileChooser chooser = FileChooserFactory.getKeyStoreFileChooser(m_keyStoreWrap.getKeyStoreType());

		File fLastDir = m_lastDir.getLastDir();
		if (fLastDir != null)
		{
			chooser.setCurrentDirectory(fLastDir);
		}

		chooser.setDialogTitle(RB.getString("FPortecle.SaveKeyStoreAs.Title"));
		chooser.setMultiSelectionEnabled(false);

		int iRtnValue = chooser.showSaveDialog(this);
		if (iRtnValue == JFileChooser.APPROVE_OPTION)
		{
			File fSaveFile = chooser.getSelectedFile();

			try
			{
				if (!confirmOverwrite(fSaveFile, RB.getString("FPortecle.SaveKeyStoreAs.Title")))
				{
					return false;
				}

				// Save the keystore to file
				m_keyStoreWrap.setKeyStore(
				    KeyStoreUtil.saveKeyStore(m_keyStoreWrap.getKeyStore(), fSaveFile, cPassword));

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
			catch (FileNotFoundException ex)
			{
				JOptionPane.showMessageDialog(this,
				    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fSaveFile),
				    RB.getString("FPortecle.SaveKeyStoreAs.Title"), JOptionPane.WARNING_MESSAGE);
				return false;
			}
			catch (Exception ex)
			{
				DThrowable.showAndWait(this, null, ex);
				return false;
			}
		}
		return false;
	}

	/**
	 * Check if the currently opened keystore requires to be saved.
	 *
	 * @return True if the keystore has been changed since the last open/save, false otherwise
	 */
	/* package private */boolean needSave()
	{
		return (m_keyStoreWrap != null && m_keyStoreWrap.isChanged());
	}

	/**
	 * Ask the user if they want to save the current keystore file.
	 *
	 * @return JOptionPane.YES_OPTION, JOptionPane.NO_OPTION or JOptionPane.CANCEL_OPTION; JOptionPane.CLOSED_OPTION is
	 *         reported as JOptionPane.CANCEL_OPTION
	 */
	/* package private */int wantSave()
	{
		assert m_keyStoreWrap != null;
		assert m_keyStoreWrap.getKeyStore() != null;

		File fKeyStoreFile = m_keyStoreWrap.getKeyStoreFile();
		String sKeyStoreName;

		if (fKeyStoreFile == null)
		{
			sKeyStoreName = RB.getString("FPortecle.Untitled");
		}
		else
		{
			sKeyStoreName = fKeyStoreFile.getName();
		}

		String sMessage = MessageFormat.format(RB.getString("FPortecle.WantSaveChanges.message"), sKeyStoreName);

		int iSelected = JOptionPane.showConfirmDialog(this, sMessage, RB.getString("FPortecle.WantSaveChanges.Title"),
		    JOptionPane.YES_NO_CANCEL_OPTION);
		if (iSelected == JOptionPane.CLOSED_OPTION)
		{
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
			// Ask user for keystore type
			DNewKeyStoreType dNewKeyStoreType = new DNewKeyStoreType(this);
			dNewKeyStoreType.setLocationRelativeTo(this);
			SwingHelper.showAndWait(dNewKeyStoreType);

			KeyStoreType keyStoreType = dNewKeyStoreType.getKeyStoreType();

			// No keystore type chosen
			if (keyStoreType == null)
			{
				return false;
			}

			// Create new keystore
			KeyStore newKeyStore = KeyStoreUtil.createKeyStore(keyStoreType);

			// Update the keystore wrapper
			m_keyStoreWrap = new KeyStoreWrapper(newKeyStore);

			// Update the frame's components and title
			selectedAlias = null;
			updateControls();
			updateTitle();

			return true;
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}
	}

	/**
	 * Let the user examine the contents of a certificate file.
	 *
	 * @param fCertFile File to load the certificate from; if <code>null</code>, prompt user
	 */
	private void examineCert(File fCertFile)
	{
		if (fCertFile == null)
		{
			fCertFile = chooseExamineCertFile();
		}
		if (fCertFile == null)
		{
			return;
		}

		m_lastDir.updateLastDir(fCertFile);

		// Show the certificates
		DViewCertificate.showAndWait(this, fCertFile);
	}

	/**
	 * Let the user examine the contents of a certificate file from a SSL connection.
	 *
	 * @param ia socket address for the SSL connection to examine
	 * @return True if the user was able to examine the certificate, false otherwise
	 */
	private boolean examineCertSSL(InetSocketAddress ia)
	{
		if (ia == null)
		{
			ia = chooseExamineCertSSL();
		}
		if (ia == null)
		{
			return false;
		}

		// TODO: options from user
		boolean bVerifyCerts = false;
		int timeOut = 10000;

		// Get the certificates received from the connection
		X509Certificate[] certs = null;
		String protocol = null;
		String cipherSuite = null;
		SSLSocket ss = null;
		Socket socket = null;

		try
		{

			SSLSocketFactory sf;
			if (bVerifyCerts)
			{
				sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
			}
			else
			{
				// @@@TODO: cache all this?
				SSLContext sc = SSLContext.getInstance("SSL");
				X509TrustManager[] tm = { new X509TrustManager()
				{
					@Override
					public void checkClientTrusted(X509Certificate[] chain, String authType)
					{
						// Trust anything
					}

					@Override
					public void checkServerTrusted(X509Certificate[] chain, String authType)
					{
						// Trust anything
					}

					@Override
					public X509Certificate[] getAcceptedIssuers()
					{
						return new X509Certificate[0];
					}
				} };
				if (m_rnd == null)
				{
					m_rnd = new SecureRandom();
				}
				sc.init(null, tm, m_rnd);
				sf = sc.getSocketFactory();
			}

			// Go through a regular SocketFactory in order to be able to:
			// - control connection timeouts before connecting, and
			// - be able to use a host(String), port based method; otherwise apparently no SNI

			socket = SocketFactory.getDefault().createSocket();
			socket.setSoTimeout(timeOut);
			socket.connect(ia, timeOut);
			ss = (SSLSocket) sf.createSocket(socket, ia.getHostString(), ia.getPort(), false);

			SSLSession sess = ss.getSession();
			// TODO: fails with GNU Classpath: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=29692
			certs = (X509Certificate[]) sess.getPeerCertificates();
			protocol = sess.getProtocol();
			cipherSuite = sess.getCipherSuite();
			sess.invalidate();
		}
		catch (Exception e)
		{
			DThrowable.showAndWait(this, null, e);
			return false;
		}
		finally
		{
			if (ss != null && !ss.isClosed())
			{
				try
				{
					ss.close();
				}
				catch (IOException e)
				{
					DThrowable.showAndWait(this, null, e);
				}
			}
			if (socket != null && !socket.isClosed())
			{
				try
				{
					socket.close();
				}
				catch (IOException e)
				{
					DThrowable.showAndWait(this, null, e);
				}
			}
		}

		// Check what we got

		try
		{
			// If there are any display the view certificate dialog with them
			if (certs != null && certs.length != 0)
			{
				DViewCertificate dViewCertificate =
				    new DViewCertificate(this, MessageFormat.format(RB.getString("FPortecle.CertDetailsSSL.Title"),
				        ia.getHostName() + ":" + ia.getPort()), certs, protocol, cipherSuite);
				dViewCertificate.setLocationRelativeTo(this);
				SwingHelper.showAndWait(dViewCertificate);
				return true;
			}
			return false;
		}
		catch (CryptoException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}
	}

	/**
	 * Let the user examine the contents of a CSR file.
	 *
	 * @param fCSRFile File to load the CSR from; if <code>null</code>, prompt user
	 * @return True if the user was able to examine the CSR file, false otherwise
	 */
	private boolean examineCSR(File fCSRFile)
	{
		if (fCSRFile == null)
		{
			fCSRFile = chooseExamineCSRFile();
		}
		if (fCSRFile == null)
		{
			return false;
		}

		// Get the CSR contained within the file
		PKCS10CertificationRequest csr = openCSR(fCSRFile);

		m_lastDir.updateLastDir(fCSRFile);

		// If a CSR is available then display the view CSR dialog with it
		if (csr != null)
		{
			try
			{
				DViewCSR dViewCSR = new DViewCSR(this,
				    MessageFormat.format(RB.getString("FPortecle.CsrDetailsFile.Title"), fCSRFile.getName()), csr);
				dViewCSR.setLocationRelativeTo(this);
				SwingHelper.showAndWait(dViewCSR);
				return true;
			}
			catch (CryptoException e)
			{
				DThrowable.showAndWait(this, null, e);
			}
		}
		return false;
	}

	/**
	 * Let the user examine the contents of a CRL file.
	 *
	 * @param fCRLFile File to load the CRL from; if <code>null</code>, prompt user
	 */
	private void examineCRL(File fCRLFile)
	{
		if (fCRLFile == null)
		{
			fCRLFile = chooseExamineCRLFile();
		}
		if (fCRLFile == null)
		{
			return;
		}

		m_lastDir.updateLastDir(fCRLFile);

		// Show the CRL
		DViewCRL.showAndWait(this, fCRLFile);
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

		chooser.setDialogTitle(RB.getString("FPortecle.ImportCaReply.Title"));
		chooser.setMultiSelectionEnabled(false);

		int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.ImportCaReply.button"));
		if (iRtnValue == JFileChooser.APPROVE_OPTION)
		{
			return chooser.getSelectedFile();
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

		chooser.setDialogTitle(RB.getString("FPortecle.ExamineCertificate.Title"));
		chooser.setMultiSelectionEnabled(false);

		int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.ExamineCertificate.button"));
		if (iRtnValue == JFileChooser.APPROVE_OPTION)
		{
			return chooser.getSelectedFile();
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
		DGetHostPort d = new DGetHostPort(this, RB.getString("FPortecle.ExamineCertificateSSL.Title"), null);
		d.setLocationRelativeTo(this);
		SwingHelper.showAndWait(d);
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
		if (fLastDir != null)
		{
			chooser.setCurrentDirectory(fLastDir);
		}

		chooser.setDialogTitle(RB.getString("FPortecle.ExamineCsr.Title"));
		chooser.setMultiSelectionEnabled(false);

		int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.ExamineCsr.button"));
		if (iRtnValue == JFileChooser.APPROVE_OPTION)
		{
			return chooser.getSelectedFile();
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

		chooser.setDialogTitle(RB.getString("FPortecle.ExamineCrl.Title"));
		chooser.setMultiSelectionEnabled(false);

		int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.ExamineCrl.button"));
		if (iRtnValue == JFileChooser.APPROVE_OPTION)
		{
			return chooser.getSelectedFile();
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
		if (fLastDir != null)
		{
			chooser.setCurrentDirectory(fLastDir);
		}

		chooser.setDialogTitle(RB.getString("FPortecle.ImportTrustCert.Title"));
		chooser.setMultiSelectionEnabled(false);

		int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.ImportTrustCert.button"));
		if (iRtnValue == JFileChooser.APPROVE_OPTION)
		{
			return chooser.getSelectedFile();
		}
		return null;
	}

	/**
	 * Let the user choose a file to import from.
	 *
	 * @return The chosen file or null if none was chosen
	 */
	private File chooseImportFile()
	{
		assert m_keyStoreWrap != null;
		assert m_keyStoreWrap.getKeyStore() != null;

		JFileChooser chooser = FileChooserFactory.getKeyPairFileChooser(null);

		File fLastDir = m_lastDir.getLastDir();
		if (fLastDir != null)
		{
			chooser.setCurrentDirectory(fLastDir);
		}

		chooser.setDialogTitle(RB.getString("FPortecle.ImportKeyPairFile.Title"));
		chooser.setMultiSelectionEnabled(false);

		int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.ImportKeyPairFile.button"));
		if (iRtnValue == JFileChooser.APPROVE_OPTION)
		{
			return chooser.getSelectedFile();
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
		if (fLastDir != null)
		{
			chooser.setCurrentDirectory(fLastDir);
		}

		chooser.setDialogTitle(RB.getString("FPortecle.GenerateCsr.Title"));
		chooser.setMultiSelectionEnabled(false);

		int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.GenerateCsr.button"));
		if (iRtnValue == JFileChooser.APPROVE_OPTION)
		{
			return chooser.getSelectedFile();
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
			URL url = fCertFile.toURI().toURL();

			ArrayList<Exception> exs = new ArrayList<>();
			X509Certificate[] certs = X509CertUtil.loadCertificates(url, exs);

			if (certs == null)
			{
				// None of the types worked - show each of the errors?
				int iSelected = SwingHelper.showConfirmDialog(this,
				    MessageFormat.format(RB.getString("FPortecle.NoOpenCertificate.message"), fCertFile),
				    RB.getString("FPortecle.OpenCertificate.Title"));
				if (iSelected == JOptionPane.YES_OPTION)
				{
					for (Exception e : exs)
					{
						DThrowable.showAndWait(this, null, e);
					}
				}
			}
			else if (certs.length == 0)
			{
				JOptionPane.showMessageDialog(this,
				    MessageFormat.format(RB.getString("FPortecle.NoCertsFound.message"), fCertFile),
				    RB.getString("FPortecle.OpenCertificate.Title"), JOptionPane.WARNING_MESSAGE);
			}

			return certs;
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
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
		try
		{
			return X509CertUtil.loadCSR(fCSRFile.toURI().toURL());
		}
		catch (FileNotFoundException ex)
		{
			JOptionPane.showMessageDialog(this,
			    MessageFormat.format(RB.getString("FPortecle.NoRead.message"), fCSRFile),
			    MessageFormat.format(RB.getString("FPortecle.CsrDetailsFile.Title"), fCSRFile.getName()),
			    JOptionPane.WARNING_MESSAGE);
			return null;
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
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
		String sAlias = m_jtKeyStore.getSelectedAlias();
		if (sAlias == null)
		{
			return false;
		}

		// Get the keystore
		KeyStore keyStore = m_keyStoreWrap.getKeyStore();

		// Let the user choose a file for the trusted certificate
		File fCertFile = chooseImportCAFile();
		if (fCertFile == null)
		{
			return false;
		}

		// Load the certificate(s)
		X509Certificate[] certs = openCert(fCertFile);

		if (certs == null || certs.length == 0)
		{
			return false;
		}

		try
		{
			// Order the new certificates into a chain...
			certs = X509CertUtil.orderX509CertChain(certs);

			// ...and those that exist in the entry already
			X509Certificate[] oldCerts =
			    X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(keyStore.getCertificateChain(sAlias)));

			// Compare the public keys of the start of each chain
			if (!oldCerts[0].getPublicKey().equals(certs[0].getPublicKey()))
			{
				JOptionPane.showMessageDialog(this, RB.getString("FPortecle.NoMatchPubKeyCaReply.message"),
				    RB.getString("FPortecle.ImportCaReply.Title"), JOptionPane.ERROR_MESSAGE);
				return false;
			}

			// If the CA certificates keystore is to be used and it has yet to be loaded then do so
			if (m_bUseCaCerts && m_caCertsKeyStore == null)
			{
				m_caCertsKeyStore = openCaCertsKeyStore();
				if (m_caCertsKeyStore == null)
				{
					// Failed to load CA certificates keystore
					return false;
				}
			}

			// Holds the new certificate chain for the entry should the import succeed
			X509Certificate[] newCertChain;

			/*
			 * PKCS #7 reply - try and match the self-signed root with any of the certificates in the CA certificates or
			 * current keystore
			 */
			if (certs.length > 1)
			{
				X509Certificate rootCert = certs[certs.length - 1];
				String sMatchAlias = null;

				if (m_bUseCaCerts) // Match against CA certificates keystore
				{
					sMatchAlias = X509CertUtil.matchCertificate(m_caCertsKeyStore, rootCert);
				}

				if (sMatchAlias == null) // Match against current keystore
				{
					sMatchAlias = X509CertUtil.matchCertificate(keyStore, rootCert);
				}

				// No match
				if (sMatchAlias == null)
				{
					// Tell the user what is happening
					JOptionPane.showMessageDialog(this, RB.getString("FPortecle.NoMatchRootCertCaReplyConfirm.message"),
					    RB.getString("FPortecle.ImportCaReply.Title"), JOptionPane.INFORMATION_MESSAGE);

					// Display the certificate to the user
					DViewCertificate dViewCertificate = new DViewCertificate(this,
					    MessageFormat.format(RB.getString("FPortecle.CertDetails.Title"), fCertFile.getName()),
					    new X509Certificate[] { rootCert });
					dViewCertificate.setLocationRelativeTo(this);
					SwingHelper.showAndWait(dViewCertificate);

					// Request confirmation that the certificate is to be trusted
					int iSelected = JOptionPane.showConfirmDialog(this, RB.getString("FPortecle.AcceptCaReply.message"),
					    RB.getString("FPortecle.ImportCaReply.Title"), JOptionPane.YES_NO_OPTION);
					if (iSelected != JOptionPane.YES_OPTION)
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
			// Single X.509 certificate reply - try and establish a chain of trust from the certificate and
			// ending with a root CA self-signed certificate
			else
			{
				KeyStore[] compKeyStores;

				// Establish against CA certificates keystore and current keystore
				if (m_bUseCaCerts)
				{
					compKeyStores = new KeyStore[] { m_caCertsKeyStore, keyStore };
				}
				else
				// Establish against current keystore only
				{
					compKeyStores = new KeyStore[] { keyStore };
				}

				X509Certificate[] trustChain = X509CertUtil.establishTrust(compKeyStores, certs[0]);

				if (trustChain == null)
				{
					JOptionPane.showMessageDialog(this, RB.getString("FPortecle.NoTrustCaReply.message"),
					    RB.getString("FPortecle.ImportCaReply.Title"), JOptionPane.ERROR_MESSAGE);
					return false;
				}

				newCertChain = trustChain;
			}

			// Get the entry's password (we may already know it from the wrapper)
			char[] cPassword = m_keyStoreWrap.getEntryPassword(sAlias);

			if (cPassword == null)
			{
				cPassword = KeyStoreUtil.DUMMY_PASSWORD;

				if (m_keyStoreWrap.getKeyStoreType().isEntryPasswordSupported())
				{
					DGetPassword dGetPassword =
					    new DGetPassword(this, RB.getString("FPortecle.KeyEntryPassword.Title"));
					dGetPassword.setLocationRelativeTo(this);
					SwingHelper.showAndWait(dGetPassword);
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

			// Update the keystore wrapper
			m_keyStoreWrap.setChanged(true);
			m_keyStoreWrap.setEntryPassword(sAlias, cPassword);

			// Update the frame's components and title
			updateControls();
			updateTitle();

			m_lastDir.updateLastDir(fCertFile);

			// Display success message
			JOptionPane.showMessageDialog(this, RB.getString("FPortecle.ImportCaReplySuccessful.message"),
			    RB.getString("FPortecle.ImportCaReply.Title"), JOptionPane.INFORMATION_MESSAGE);

			return true;
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}
	}

	/**
	 * Let the user renew a self-signed certificate for the selected key pair entry.
	 *
	 * @return True if the renewal is successful, false otherwise
	 */
	private boolean renewSelectedEntry()
	{
		assert m_keyStoreWrap != null;
		assert m_keyStoreWrap.getKeyStore() != null;

		// What entry is selected?
		String sAlias = m_jtKeyStore.getSelectedAlias();
		if (sAlias == null)
		{
			return false;
		}

		// Get the keystore
		KeyStore keyStore = m_keyStoreWrap.getKeyStore();

		try
		{
			// Get the entry's password (we may already know it from the wrapper)
			char[] cPassword = m_keyStoreWrap.getEntryPassword(sAlias);

			if (cPassword == null)
			{
				cPassword = KeyStoreUtil.DUMMY_PASSWORD;

				if (m_keyStoreWrap.getKeyStoreType().isEntryPasswordSupported())
				{
					DGetPassword dGetPassword =
					    new DGetPassword(this, RB.getString("FPortecle.KeyEntryPassword.Title"));
					dGetPassword.setLocationRelativeTo(this);
					SwingHelper.showAndWait(dGetPassword);
					cPassword = dGetPassword.getPassword();

					if (cPassword == null)
					{
						return false;
					}
				}
			}

			// TODO: ask from user
			int renewalDays = 365;

			KeyStore.PrivateKeyEntry entry =
			    (KeyStore.PrivateKeyEntry) keyStore.getEntry(sAlias, new KeyStore.PasswordProtection(cPassword));
			PrivateKey privateKey = entry.getPrivateKey();
			X509Certificate oldCert = (X509Certificate) entry.getCertificate();
			PublicKey publicKey = oldCert.getPublicKey();

			X509Certificate newCert = X509CertUtil.renewCert(oldCert, renewalDays, publicKey, privateKey);

			KeyStore.PrivateKeyEntry newEntry = new KeyStore.PrivateKeyEntry(privateKey, new Certificate[] { newCert });

			if (keyStore.containsAlias(sAlias))
			{
				keyStore.deleteEntry(sAlias);
			}
			keyStore.setEntry(sAlias, newEntry, new KeyStore.PasswordProtection(cPassword));

			// Update the keystore wrapper
			m_keyStoreWrap.setChanged(true);
			m_keyStoreWrap.setEntryPassword(sAlias, new char[0]);

			// Update the frame's components and title
			updateControls();
			updateTitle();

			// Display success message
			JOptionPane.showMessageDialog(this, RB.getString("FPortecle.RenewSelfSignedSuccessful.message"),
			    RB.getString("FPortecle.RenewSelfSigned.Title"), JOptionPane.INFORMATION_MESSAGE);

			return true;
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
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

		if (certs == null || certs.length == 0)
		{
			return false;
		}

		if (certs.length > 1)
		{
			// Cannot import more than one certificate
			JOptionPane.showMessageDialog(this, RB.getString("FPortecle.NoMultipleTrustCertImport.message"),
			    RB.getString("FPortecle.ImportTrustCert.Title"), JOptionPane.ERROR_MESSAGE);
			return false;
		}

		X509Certificate trustCert = certs[0];

		try
		{
			// Get the keystore
			KeyStore keyStore = m_keyStoreWrap.getKeyStore();

			// Certificate already exists in the keystore
			String sMatchAlias = X509CertUtil.matchCertificate(keyStore, trustCert);
			if (sMatchAlias != null)
			{
				int iSelected = JOptionPane.showConfirmDialog(this,
				    MessageFormat.format(RB.getString("FPortecle.TrustCertExistsConfirm.message"), sMatchAlias),
				    RB.getString("FPortecle.ImportTrustCert.Title"), JOptionPane.YES_NO_OPTION);
				if (iSelected != JOptionPane.YES_OPTION)
				{
					return false;
				}
			}

			// If the CA certificates keystore is to be used and it has yet to be loaded then do so
			if (m_bUseCaCerts && m_caCertsKeyStore == null)
			{
				m_caCertsKeyStore = openCaCertsKeyStore();
				if (m_caCertsKeyStore == null)
				{
					// Failed to load CA certificates keystore
					return false;
				}
			}

			// If we cannot establish trust for the certificate against the CA certificates keystore or the
			// current keystore then, display the certificate to the user for confirmation
			KeyStore[] compKeyStores;

			// Establish against CA certificates keystore and current keystore
			if (m_bUseCaCerts)
			{
				compKeyStores = new KeyStore[] { m_caCertsKeyStore, keyStore };
			}
			else
			// Establish against current keystore only
			{
				compKeyStores = new KeyStore[] { keyStore };
			}

			if (X509CertUtil.establishTrust(compKeyStores, trustCert) == null)
			{
				// Tell the user what is happening
				JOptionPane.showMessageDialog(this, RB.getString("FPortecle.NoTrustPathCertConfirm.message"),
				    RB.getString("FPortecle.ImportTrustCert.Title"), JOptionPane.INFORMATION_MESSAGE);

				// Display the certificate to the user
				DViewCertificate dViewCertificate = new DViewCertificate(this,
				    MessageFormat.format(RB.getString("FPortecle.CertDetails.Title"), fCertFile.getName()),
				    new X509Certificate[] { trustCert });
				dViewCertificate.setLocationRelativeTo(this);
				SwingHelper.showAndWait(dViewCertificate);

				// Request confirmation that the certificate is to be trusted
				int iSelected = JOptionPane.showConfirmDialog(this, RB.getString("FPortecle.AcceptTrustCert.message"),
				    RB.getString("FPortecle.ImportTrustCert.Title"), JOptionPane.YES_NO_OPTION);
				if (iSelected != JOptionPane.YES_OPTION)
				{
					return false;
				}
			}

			String sAlias = X509CertUtil.getCertificateAlias(trustCert).toLowerCase();
			sAlias = getNewEntryAlias(keyStore, sAlias, "FPortecle.TrustCertEntryAlias.Title", false);
			if (sAlias == null)
			{
				return false;
			}

			// Delete old entry first
			if (keyStore.containsAlias(sAlias))
			{
				keyStore.deleteEntry(sAlias);
			}

			// Import the trusted certificate
			keyStore.setCertificateEntry(sAlias, trustCert);

			// Update the keystore wrapper
			m_keyStoreWrap.setChanged(true);

			// Update the frame's components and title
			selectedAlias = sAlias;
			updateControls();
			updateTitle();

			m_lastDir.updateLastDir(fCertFile);

			// Display success message
			JOptionPane.showMessageDialog(this, RB.getString("FPortecle.ImportTrustCertSuccessful.message"),
			    RB.getString("FPortecle.ImportTrustCert.Title"), JOptionPane.INFORMATION_MESSAGE);

			return true;
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}
	}

	/**
	 * Let the user import a key pair a PKCS #12 keystore or a PEM bundle.
	 *
	 * @return True if the import is successful, false otherwise
	 */
	private boolean importKeyPair()
	{
		assert m_keyStoreWrap != null;
		assert m_keyStoreWrap.getKeyStore() != null;

		KeyStore keyStore = m_keyStoreWrap.getKeyStore();

		// Let the user choose a file to import from
		File fKeyPairFile = chooseImportFile();
		if (fKeyPairFile == null)
		{
			return false;
		}

		m_lastDir.updateLastDir(fKeyPairFile);

		// Not a file?
		if (!fKeyPairFile.isFile())
		{
			JOptionPane.showMessageDialog(this,
			    MessageFormat.format(RB.getString("FPortecle.NotFile.message"), fKeyPairFile),
			    RB.getString("FPortecle.ImportKeyPair.Title"), JOptionPane.WARNING_MESSAGE);
			return false;
		}

		ArrayList<Exception> exceptions = new ArrayList<>();

		PasswordFinder passwordFinder = new PasswordFinder()
		{
			private int passwordNumber = 1;

			@Override
			public char[] getPassword()
			{
				// Get the user to enter the private key password
				DGetPassword dGetPassword = new DGetPassword(FPortecle.this, MessageFormat.format(
				    RB.getString("FPortecle.PrivateKeyPassword.Title"), String.valueOf(passwordNumber)));
				dGetPassword.setLocationRelativeTo(FPortecle.this);
				SwingHelper.showAndWait(dGetPassword);
				char[] cPassword = dGetPassword.getPassword();
				passwordNumber++;
				return cPassword;
			}
		};

		KeyStore tempStore = null;
		try (PEMParser reader = new PEMParser(new FileReader(fKeyPairFile.getPath())))
		{
			tempStore = KeyStoreUtil.loadEntries(reader, passwordFinder);
			if (tempStore.size() == 0)
			{
				tempStore = null;
			}
		}
		catch (Exception e)
		{
			exceptions.add(e);
		}

		// Treat as PKCS #12 keystore
		if (tempStore == null)
		{
			// Get the user to enter the PKCS #12 keystore's password
			DGetPassword dGetPassword = new DGetPassword(this, RB.getString("FPortecle.Pkcs12Password.Title"));
			dGetPassword.setLocationRelativeTo(this);
			SwingHelper.showAndWait(dGetPassword);

			char[] cPkcs12Password = dGetPassword.getPassword();
			if (cPkcs12Password == null)
			{
				return false;
			}

			// Load the PKCS #12 keystore
			try
			{
				tempStore = KeyStoreUtil.loadKeyStore(fKeyPairFile, cPkcs12Password, KeyStoreType.PKCS12);
			}
			catch (Exception e)
			{
				exceptions.add(e);
			}
		}

		if (tempStore == null && !exceptions.isEmpty())
		{
			int iSelected = SwingHelper.showConfirmDialog(this,
			    MessageFormat.format(RB.getString("FPortecle.NoOpenKeyPairFile.message"), fKeyPairFile),
			    RB.getString("FPortecle.ImportKeyPairFile.Title"));
			if (iSelected == JOptionPane.YES_OPTION)
			{
				for (Exception e : exceptions)
				{
					DThrowable.showAndWait(this, null, e);
				}
			}

			return false;
		}

		try
		{
			// Display the import key pair dialog supplying the PKCS #12 keystore to it
			DImportKeyPair dImportKeyPair = new DImportKeyPair(this, tempStore);
			dImportKeyPair.setLocationRelativeTo(this);
			SwingHelper.showAndWait(dImportKeyPair);

			// Get the private key and certificate chain of the key pair
			Key privateKey = dImportKeyPair.getPrivateKey();
			Certificate[] certs = dImportKeyPair.getCertificateChain();

			if (privateKey == null || certs == null)
			{
				// User did not select a key pair for import
				return false;
			}

			// Get an alias for the new keystore entry
			String sAlias = dImportKeyPair.getAlias();
			if (sAlias == null)
			{
				sAlias = X509CertUtil.getCertificateAlias(X509CertUtil.convertCertificate(certs[0]));
			}
			sAlias = getNewEntryAlias(keyStore, sAlias, "FPortecle.KeyPairEntryAlias.Title", false);
			if (sAlias == null)
			{
				return false;
			}

			// Get a password for the new keystore entry if applicable
			char[] cPassword = KeyStoreUtil.DUMMY_PASSWORD;

			if (m_keyStoreWrap.getKeyStoreType().isEntryPasswordSupported())
			{
				DGetNewPassword dGetNewPassword =
				    new DGetNewPassword(this, RB.getString("FPortecle.KeyEntryPassword.Title"));
				dGetNewPassword.setLocationRelativeTo(this);
				SwingHelper.showAndWait(dGetNewPassword);
				cPassword = dGetNewPassword.getPassword();

				if (cPassword == null)
				{
					return false;
				}
			}

			// Delete old entry first
			if (keyStore.containsAlias(sAlias))
			{
				keyStore.deleteEntry(sAlias);
			}

			// Place the private key and certificate chain into the keystore and update the keystore wrapper
			keyStore.setKeyEntry(sAlias, privateKey, cPassword, certs);
			m_keyStoreWrap.setEntryPassword(sAlias, cPassword);
			m_keyStoreWrap.setChanged(true);

			// Update the frame's components and title
			selectedAlias = sAlias;
			updateControls();
			updateTitle();

			// Display success message
			JOptionPane.showMessageDialog(this, RB.getString("FPortecle.KeyPairImportSuccessful.message"),
			    RB.getString("FPortecle.ImportKeyPair.Title"), JOptionPane.INFORMATION_MESSAGE);
			return true;
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}
	}

	/**
	 * Open the CA certificates keystore from disk.
	 *
	 * @return The keystore if it could be opened or null otherwise
	 */
	private KeyStore openCaCertsKeyStore()
	{
		// Get the user to enter the CA certificates keystore's password
		DGetPassword dGetPassword = new DGetPassword(this, RB.getString("FPortecle.CaCertsKeyStorePassword.Title"));
		dGetPassword.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dGetPassword);
		char[] cPassword = dGetPassword.getPassword();

		if (cPassword == null)
		{
			return null;
		}

		try
		{
			// Load the CA certificates keystore - try to open as each of the allowed types in turn until
			// successful
			KeyStore caCertsKeyStore = null;

			// Types
			KeyStoreType[] keyStoreTypes = KeyStoreUtil.getAvailableTypes();

			// Exceptions
			CryptoException[] cexs = new CryptoException[keyStoreTypes.length];

			// Tried types
			StringBuilder tried = new StringBuilder();

			for (int iCnt = 0; iCnt < keyStoreTypes.length; iCnt++)
			{
				tried.append(", ").append(keyStoreTypes[iCnt]);
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
				if (tried.length() > 2)
				{
					tried.delete(0, 2); // Chop leading ", "
				}
				int iSelected = SwingHelper.showConfirmDialog(this,
				    MessageFormat.format(RB.getString("FPortecle.NoOpenCaCertsKeyStore.message"), m_fCaCertsFile,
				        tried),
				    RB.getString("FPortecle.OpenCaCertsKeyStore.Title"));
				if (iSelected == JOptionPane.YES_OPTION)
				{
					for (CryptoException cex : cexs)
					{
						DThrowable.showAndWait(this, null, cex);
					}
				}

				return null;
			}

			return caCertsKeyStore;
		}
		catch (FileNotFoundException ex)
		{
			JOptionPane.showMessageDialog(this,
			    MessageFormat.format(RB.getString("FPortecle.NoRead.message"), m_fCaCertsFile),
			    RB.getString("FPortecle.OpenCaCertsKeyStore.Title"), JOptionPane.WARNING_MESSAGE);
			return null;
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
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
			URL toc;
			URL home;
			String s = RB.getString("FPortecle.Help.Contents");
			if (s.startsWith("/"))
			{
				toc = FPortecle.class.getResource(s);
			}
			else
			{
				try
				{
					toc = new URL(s);
				}
				catch (MalformedURLException e)
				{
					DThrowable.showAndWait(this, null, e);
					return;
				}
			}
			s = RB.getString("FPortecle.Help.Home");
			if (s.startsWith("/"))
			{
				home = FPortecle.class.getResource(s);
			}
			else
			{
				try
				{
					home = new URL(s);
				}
				catch (MalformedURLException e)
				{
					DThrowable.showAndWait(this, null, e);
					return;
				}
			}

			m_fHelp = new FHelp(RB.getString("FPortecle.Help.Title"), home, toc);
			m_fHelp.setLocation(getX() + 25, getY() + 25);
		}

		// Show the help dialog
		SwingHelper.showAndWait(m_fHelp);
	}

	/**
	 * Display application's web site.
	 */
	private void visitWebsite()
	{
		DesktopUtil.browse(this, URI.create(RB.getString("FPortecle.WebsiteAddress")));
	}

	/**
	 * Display Portecle project page at SourceForge.net.
	 */
	private void visitSFNetProject()
	{
		DesktopUtil.browse(this, URI.create(RB.getString("FPortecle.SFNetProjectAddress")));
	}

	/**
	 * Display donation web page.
	 */
	private void makeDonation()
	{
		DesktopUtil.browse(this, URI.create(RB.getString("FPortecle.DonateAddress")));
	}

	/**
	 * Display Security Provider Information dialog.
	 */
	private void showSecurityProviders()
	{
		DProviderInfo dProviderInfo = new DProviderInfo(this);
		dProviderInfo.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dProviderInfo);
	}

	/**
	 * Display JAR Information dialog.
	 */
	private void showJarInfo()
	{
		try
		{
			DJarInfo dJarInfo = new DJarInfo(this);
			dJarInfo.setLocationRelativeTo(this);
			SwingHelper.showAndWait(dJarInfo);
		}
		catch (IOException ex)
		{
			DThrowable.showAndWait(this, null, ex);
		}
	}

	/**
	 * Display the options dialog and store the user's choices.
	 */
	private void showOptions()
	{
		DOptions dOptions = new DOptions(this, m_bUseCaCerts, m_fCaCertsFile, m_bBouncyCastleAllowUnsafeInteger);
		dOptions.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dOptions);

		// Store/apply the chosen options:

		// CA certificates file
		File fTmp = dOptions.getCaCertsFile();

		if (!fTmp.equals(m_fCaCertsFile))
		{
			// CA certificates file changed - any stored CA certificates keystore is now invalid
			m_caCertsKeyStore = null;
		}

		m_fCaCertsFile = fTmp;

		// Use CA certificates?
		m_bUseCaCerts = dOptions.isUseCaCerts();
		
		// Allowed to set option for BC
		m_bBouncyCastleAllowUnsafeInteger =dOptions.isBcAllowUnsafeInteger();
		if(m_bBouncyCastleAllowUnsafeInteger)
		{
			System.getProperties().setProperty(RB.getString("AppPrefs.BouncyCastleAllowUnsafeIntegerOption"), "true");
		}
		else
		{
			System.getProperties().remove(RB.getString("AppPrefs.BouncyCastleAllowUnsafeIntegerOption"));
		}


		// Look & feel
		String newLookFeelClassName = dOptions.getLookFeelClassName();

		// Look & feel decoration
		boolean bLookFeelDecoration = dOptions.isLookFeelDecoration();

		// Look & feel/decoration changed?
		// Note: UIManager.LookAndFeelInfo.getName() and LookAndFeel.getName() can be different for the same
		// L&F (one example is the GTK+ one in J2SE 5 RC2 (Linux), where the former is "GTK+" and the latter
		// is "GTK look and feel"). Therefore, compare the class names instead.
		if (newLookFeelClassName != null &&
		    (!newLookFeelClassName.equals(UIManager.getLookAndFeel().getClass().getName()) ||
		        bLookFeelDecoration != JFrame.isDefaultLookAndFeelDecorated()))
		{
			// Yes - save selections to be picked up by application preferences,
			lookFeelClassName = newLookFeelClassName;
			m_bLookFeelDecorationOptions = bLookFeelDecoration;
			saveAppPrefs();

			JFrame.setDefaultLookAndFeelDecorated(bLookFeelDecoration);
			JDialog.setDefaultLookAndFeelDecorated(bLookFeelDecoration);
			try
			{
				UIManager.setLookAndFeel(lookFeelClassName);
				SwingUtilities.updateComponentTreeUI(getRootPane());
				pack();
			}
			catch (Exception e)
			{
				DThrowable.showAndWait(this, null, e);
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
		assert !m_keyStoreWrap.getKeyStore().getType().equals(keyStoreType.name());

		try
		{
			// Get current keystore and type
			KeyStore currentKeyStore = m_keyStoreWrap.getKeyStore();
			KeyStoreType currentType = m_keyStoreWrap.getKeyStoreType();

			// Create empty keystore of new type
			KeyStore newKeyStore = KeyStoreUtil.createKeyStore(keyStoreType);

			// Flag used to tell if we have warned the user about default key pair entry passwords for
			// keystores changed to types that don't support entry passwords
			boolean bWarnPasswordUnsupported = false;

			// Flag used to tell if we have warned the user about key entries not being carried over by the
			// change
			boolean bWarnNoChangeKey = false;

			// For every entry in the current keystore transfer it to the new one - get key/key pair entry
			// passwords from the wrapper and if not present there from the user
			for (Enumeration<String> aliases = currentKeyStore.aliases(); aliases.hasMoreElements();)
			{
				// Entry alias
				String sAlias = aliases.nextElement();

				// Trusted certificate entry
				if (currentKeyStore.isCertificateEntry(sAlias))
				{
					// Check and ask about alias overwriting issues
					if (newKeyStore.containsAlias(sAlias))
					{
						int iSelected =
						    JOptionPane.showConfirmDialog(this, RB.getString("FPortecle.WarnOverwriteAlias.message"),
						        RB.getString("FPortecle.ChangeKeyStoreType.Title"), JOptionPane.YES_NO_OPTION);
						if (iSelected != JOptionPane.YES_OPTION)
						{
							continue;
						}
					}

					// Get trusted certificate and place it in the new keystore
					Certificate trustedCertificate = currentKeyStore.getCertificate(sAlias);
					newKeyStore.setCertificateEntry(sAlias, trustedCertificate);
				}
				// Key or Key pair entry
				else if (currentKeyStore.isKeyEntry(sAlias))
				{
					// Get certificate chain - will be null if entry is key
					Certificate[] certificateChain = currentKeyStore.getCertificateChain(sAlias);

					if (certificateChain == null || certificateChain.length == 0)
					{
						// Key entries are not transferred - warn the user if we haven't done so already
						if (!bWarnNoChangeKey)
						{
							bWarnNoChangeKey = true;
							int iSelected =
							    JOptionPane.showConfirmDialog(this, RB.getString("FPortecle.WarnNoChangeKey.message"),
							        RB.getString("FPortecle.ChangeKeyStoreType.Title"), JOptionPane.YES_NO_OPTION);
							if (iSelected != JOptionPane.YES_OPTION)
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
						cPassword = KeyStoreUtil.DUMMY_PASSWORD;

						if (currentType.isEntryPasswordSupported())
						{
							String sTitle = MessageFormat.format(
							    RB.getString("FPortecle.ChangeKeyStoreTypeKeyPairEntryPassword.Title"), sAlias);
							DGetPassword dGetPassword = new DGetPassword(this, sTitle);
							dGetPassword.setLocationRelativeTo(this);
							SwingHelper.showAndWait(dGetPassword);
							cPassword = dGetPassword.getPassword();

							if (cPassword == null)
							{
								return false;
							}
						}
					}

					// Use password to get key pair
					Key key = currentKeyStore.getKey(sAlias, cPassword);

					// The current keystore type does not support entry passwords so the password will be set
					// to the "dummy value" password
					if (!currentType.isEntryPasswordSupported())
					{
						// Warn the user about this
						if (!bWarnPasswordUnsupported)
						{
							bWarnPasswordUnsupported = true;
							JOptionPane.showMessageDialog(this,
							    MessageFormat.format(RB.getString("FPortecle.ChangeFromPasswordUnsupported.message"),
							        new String(KeyStoreUtil.DUMMY_PASSWORD)),
							    RB.getString("FPortecle.ChangeKeyStoreType.Title"), JOptionPane.INFORMATION_MESSAGE);
						}
					}
					// The new keystore type does not support entry passwords so use dummy password for entry
					else if (!keyStoreType.isEntryPasswordSupported())
					{
						cPassword = KeyStoreUtil.DUMMY_PASSWORD;
					}

					// Check and ask about alias overwriting issues
					if (newKeyStore.containsAlias(sAlias))
					{
						int iSelected =
						    JOptionPane.showConfirmDialog(this, RB.getString("FPortecle.WarnOverwriteAlias.message"),
						        RB.getString("FPortecle.ChangeKeyStoreType.Title"), JOptionPane.YES_NO_OPTION);
						if (iSelected != JOptionPane.YES_OPTION)
						{
							continue;
						}
					}

					// Put key and (possibly null) certificate chain in new keystore
					newKeyStore.setKeyEntry(sAlias, key, cPassword, certificateChain);

					// Update wrapper with password
					m_keyStoreWrap.setEntryPassword(sAlias, cPassword);
				}
			}

			// Successful change of type - put new keystore into wrapper
			m_keyStoreWrap.setKeyStore(newKeyStore);
			File oldFile = m_keyStoreWrap.getKeyStoreFile();
			if (oldFile != null)
			{
				Set<String> oldExts = m_keyStoreWrap.getKeyStoreType().getFilenameExtensions();
				Set<String> newExts = keyStoreType.getFilenameExtensions();
				if (oldExts.isEmpty() || newExts.isEmpty())
				{
					m_keyStoreWrap.setKeyStoreFile(null);
				}
				else
				{
					String newExt = newExts.iterator().next();
					for (String oldExt : oldExts)
					{
						String path = oldFile.getPath().toLowerCase();
						if (path.endsWith("." + oldExt))
						{
							m_keyStoreWrap.setKeyStoreFile(
							    new File(path.substring(0, path.length() - oldExt.length()) + newExt));
						}
					}
					if (oldFile.equals(m_keyStoreWrap.getKeyStoreFile()))
					{
						m_keyStoreWrap.setKeyStoreFile(null);
					}
				}
			}
			m_keyStoreWrap.setChanged(true);

			// Update the frame's components and title
			updateControls();
			updateTitle();

			// Display success message
			JOptionPane.showMessageDialog(this, RB.getString("FPortecle.ChangeKeyStoreTypeSuccessful.message"),
			    RB.getString("FPortecle.ChangeKeyStoreType.Title"), JOptionPane.INFORMATION_MESSAGE);
			return true;
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
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

		// User canceled
		if (cPassword == null)
		{
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
		assert m_keyStoreWrap.getKeyStoreType().isEntryPasswordSupported();

		// Not valid for a certificate entry, nor a key-only one - we do a remove-store operation but the
		// KeyStore API won't allow us to store a PrivateKey without associated certificate chain.
		// TODO: Maybe it'd work for other Key types? Need testing material.
		if (!KeyStoreTableModel.KEY_PAIR_ENTRY.equals(m_jtKeyStore.getSelectedType()))
		{
			return false;
		}

		// Get entry alias
		String sAlias = m_jtKeyStore.getSelectedAlias();

		// Do we already know the current password for the entry?
		char[] cOldPassword = m_keyStoreWrap.getEntryPassword(sAlias);

		// Display the change password dialog supplying the current password to it if it was available
		DChangePassword dChangePassword =
		    new DChangePassword(this, RB.getString("FPortecle.SetKeyPairPassword.Title"), cOldPassword);
		dChangePassword.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dChangePassword);

		// Get the password settings the user made in the dialog
		if (cOldPassword == null)
		{
			cOldPassword = dChangePassword.getOldPassword();
		}
		char[] cNewPassword = dChangePassword.getNewPassword();

		// Dialog was canceled
		if (cOldPassword == null || cNewPassword == null)
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

			// Update the keystore wrapper
			m_keyStoreWrap.setEntryPassword(sAlias, cNewPassword);
			m_keyStoreWrap.setChanged(true);
		}
		catch (GeneralSecurityException ex)
		{
			DThrowable.showAndWait(this, null, ex);
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

		// TODO: implement this for key-only entries
		String selectedType = m_jtKeyStore.getSelectedType();
		if (selectedType == null || selectedType.equals(KeyStoreTableModel.KEY_ENTRY))
		{
			return false;
		}

		// Get the entry
		String sAlias = m_jtKeyStore.getSelectedAlias();

		try
		{
			// Display the Generate Key Pair dialog to get the key pair generation parameters from the user
			DExport dExport = new DExport(this, m_keyStoreWrap, sAlias);
			dExport.setLocationRelativeTo(this);
			SwingHelper.showAndWait(dExport);

			if (!dExport.exportSelected())
			{
				return false; // User canceled the dialog
			}

			// Do export
			boolean bSuccess;

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
				// Export PkiPath format
				else if (dExport.exportPkiPath())
				{
					bSuccess = exportHeadCertOnlyPkiPath(sAlias);
				}
				// Export PKCS #7 format
				else
				// if (dExport.exportPkcs7())
				{
					bSuccess = exportHeadCertOnlyPkcs7(sAlias);
				}
			}
			// Complete certification path (PKCS #7 or PkiPath)
			else if (dExport.exportChain())
			{
				if (dExport.exportPkiPath())
				{
					bSuccess = exportAllCertsPkiPath(sAlias);
				}
				else
				// if (dExport.exportPkcs7())
				{
					bSuccess = exportAllCertsPkcs7(sAlias);
				}
			}
			// Complete certification path and private key (PKCS #12)
			else
			{
				if (dExport.exportPem())
				{
					bSuccess = exportPrivKeyCertChainPEM(sAlias);
				}
				else
				// if (dExport.exportPkcs12())
				{
					bSuccess = exportPrivKeyCertChainPKCS12(sAlias);
				}
			}

			if (bSuccess)
			{
				// Display success message
				JOptionPane.showMessageDialog(this, RB.getString("FPortecle.ExportSuccessful.message"),
				    RB.getString("FPortecle.Export.Title"), JOptionPane.INFORMATION_MESSAGE);
			}
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
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
		X509Certificate cert;
		try
		{
			cert = getHeadCert(sEntryAlias);
		}
		catch (CryptoException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}

		String basename = X509CertUtil.getCertificateAlias(cert);
		if (basename.isEmpty())
		{
			basename = sEntryAlias;
		}

		// Let the user choose the export certificate file
		File fExportFile = chooseExportCertFile(basename);
		if (fExportFile == null)
		{
			return false;
		}

		if (!confirmOverwrite(fExportFile, getTitle()))
		{
			return false;
		}

		try (JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(fExportFile)))
		{
			pw.writeObject(cert);
			m_lastDir.updateLastDir(fExportFile);
			return true;
		}
		catch (FileNotFoundException ex)
		{
			String sMessage =
			    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
			JOptionPane.showMessageDialog(this, sMessage, getTitle(), JOptionPane.WARNING_MESSAGE);
			return false;
		}
		catch (IOException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
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
		X509Certificate cert;
		try
		{
			// Get the head certificate
			cert = getHeadCert(sEntryAlias);
		}
		catch (CryptoException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}

		String basename = X509CertUtil.getCertificateAlias(cert);
		if (basename.isEmpty())
		{
			basename = sEntryAlias;
		}

		// Let the user choose the export certificate file
		File fExportFile = chooseExportCertFile(basename);
		if (fExportFile == null)
		{
			return false;
		}

		if (!confirmOverwrite(fExportFile, getTitle()))
		{
			return false;
		}

		// Do the export

		byte[] bEncoded;
		try
		{
			bEncoded = X509CertUtil.getCertEncodedDer(cert);
		}
		catch (CryptoException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}

		try (FileOutputStream fos = new FileOutputStream(fExportFile))
		{
			fos.write(bEncoded);
			m_lastDir.updateLastDir(fExportFile);
			return true;
		}
		catch (FileNotFoundException ex)
		{
			String sMessage =
			    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
			JOptionPane.showMessageDialog(this, sMessage, getTitle(), JOptionPane.WARNING_MESSAGE);
			return false;
		}
		catch (IOException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
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
		X509Certificate cert;
		try
		{
			// Get the head certificate
			cert = getHeadCert(sEntryAlias);
		}
		catch (CryptoException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}

		String basename = X509CertUtil.getCertificateAlias(cert);
		if (basename.isEmpty())
		{
			basename = sEntryAlias;
		}

		// Let the user choose the export PKCS #7 file
		File fExportFile = chooseExportPKCS7File(basename);
		if (fExportFile == null)
		{
			return false;
		}

		if (!confirmOverwrite(fExportFile, getTitle()))
		{
			return false;
		}

		// Do the export

		byte[] bEncoded;
		try
		{
			bEncoded = X509CertUtil.getCertEncodedPkcs7(cert);
		}
		catch (CryptoException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}

		try (FileOutputStream fos = new FileOutputStream(fExportFile))
		{
			fos.write(bEncoded);
			m_lastDir.updateLastDir(fExportFile);
			return true;
		}
		catch (FileNotFoundException ex)
		{
			String sMessage =
			    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
			JOptionPane.showMessageDialog(this, sMessage, getTitle(), JOptionPane.WARNING_MESSAGE);
			return false;
		}
		catch (IOException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
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
		X509Certificate cert;
		try
		{
			// Get the head certificate
			cert = getHeadCert(sEntryAlias);
		}
		catch (CryptoException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}

		String basename = X509CertUtil.getCertificateAlias(cert);
		if (basename.isEmpty())
		{
			basename = sEntryAlias;
		}

		// Let the user choose the export PkiPath file
		File fExportFile = chooseExportPkiPathFile(basename);
		if (fExportFile == null)
		{
			return false;
		}

		if (!confirmOverwrite(fExportFile, getTitle()))
		{
			return false;
		}

		// Do the export

		byte[] bEncoded;
		try
		{
			bEncoded = X509CertUtil.getCertEncodedPkiPath(cert);
		}
		catch (CryptoException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}

		try (FileOutputStream fos = new FileOutputStream(fExportFile))
		{
			fos.write(bEncoded);
			m_lastDir.updateLastDir(fExportFile);
			return true;
		}
		catch (FileNotFoundException ex)
		{
			String sMessage =
			    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
			JOptionPane.showMessageDialog(this, sMessage, getTitle(), JOptionPane.WARNING_MESSAGE);
			return false;
		}
		catch (IOException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
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
		X509Certificate[] certChain;
		try
		{
			certChain = X509CertUtil.convertCertificates(keyStore.getCertificateChain(sEntryAlias));
		}
		catch (CryptoException | KeyStoreException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}

		String basename = null;
		if (certChain.length > 0)
		{
			basename = X509CertUtil.getCertificateAlias(certChain[0]);
		}
		if (basename == null || basename.isEmpty())
		{
			basename = sEntryAlias;
		}

		// Let the user choose the export PKCS #7 file
		File fExportFile = chooseExportPKCS7File(basename);
		if (fExportFile == null)
		{
			return false;
		}

		if (!confirmOverwrite(fExportFile, getTitle()))
		{
			return false;
		}

		// Do the export

		byte[] bEncoded;
		try
		{
			bEncoded = X509CertUtil.getCertsEncodedPkcs7(certChain);
		}
		catch (CryptoException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}

		try (FileOutputStream fos = new FileOutputStream(fExportFile))
		{
			fos.write(bEncoded);
			m_lastDir.updateLastDir(fExportFile);
			return true;
		}
		catch (FileNotFoundException ex)
		{
			String sMessage =
			    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
			JOptionPane.showMessageDialog(this, sMessage, getTitle(), JOptionPane.WARNING_MESSAGE);
			return false;
		}
		catch (IOException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
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
		X509Certificate[] certChain;
		try
		{
			certChain = X509CertUtil.convertCertificates(keyStore.getCertificateChain(sEntryAlias));
		}
		catch (CryptoException | KeyStoreException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}

		String basename = null;
		if (certChain.length > 0)
		{
			basename = X509CertUtil.getCertificateAlias(certChain[0]);
		}
		if (basename == null || basename.isEmpty())
		{
			basename = sEntryAlias;
		}

		// Let the user choose the export PkiPath file
		File fExportFile = chooseExportPkiPathFile(basename);
		if (fExportFile == null)
		{
			return false;
		}

		if (!confirmOverwrite(fExportFile, getTitle()))
		{
			return false;
		}

		// Do the export

		byte[] bEncoded;
		try
		{
			bEncoded = X509CertUtil.getCertsEncodedPkiPath(certChain);
		}
		catch (CryptoException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}

		try (FileOutputStream fos = new FileOutputStream(fExportFile))
		{
			fos.write(bEncoded);
			m_lastDir.updateLastDir(fExportFile);
			return true;
		}
		catch (FileNotFoundException ex)
		{
			String sMessage =
			    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
			JOptionPane.showMessageDialog(this, sMessage, getTitle(), JOptionPane.WARNING_MESSAGE);
			return false;
		}
		catch (IOException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
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
		try
		{
			// Get keystore
			KeyStore keyStore = m_keyStoreWrap.getKeyStore();

			// Get the entry's head certificate
			X509Certificate cert;
			if (keyStore.isKeyEntry(sEntryAlias))
			{
				cert = X509CertUtil.orderX509CertChain(
				    X509CertUtil.convertCertificates(keyStore.getCertificateChain(sEntryAlias)))[0];
			}
			else
			{
				cert = X509CertUtil.convertCertificate(keyStore.getCertificate(sEntryAlias));
			}

			return cert;
		}
		catch (KeyStoreException ex)
		{
			String sMessage = MessageFormat.format(RB.getString("FPortecle.NoAccessEntry.message"), sEntryAlias);
			throw new CryptoException(sMessage, ex);
		}
	}

	/**
	 * Export the private key and certificates of the keystore entry to a PEM encoded "OpenSSL" format bundle.
	 *
	 * @param sEntryAlias Entry alias
	 * @return True if the export is successful, false otherwise
	 */
	private boolean exportPrivKeyCertChainPEM(String sEntryAlias)
	{
		KeyStore keyStore = m_keyStoreWrap.getKeyStore();

		// Get the entry's password (we may already know it from the wrapper)
		char[] cPassword = m_keyStoreWrap.getEntryPassword(sEntryAlias);

		if (cPassword == null)
		{
			cPassword = KeyStoreUtil.DUMMY_PASSWORD;

			if (m_keyStoreWrap.getKeyStoreType().isEntryPasswordSupported())
			{
				DGetPassword dGetPassword = new DGetPassword(this, RB.getString("FPortecle.KeyEntryPassword.Title"));
				dGetPassword.setLocationRelativeTo(this);
				SwingHelper.showAndWait(dGetPassword);
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

			// Get a new password to encrypt the private key with
			DGetNewPassword dGetNewPassword =
			    new DGetNewPassword(this, RB.getString("FPortecle.PrivateKeyExportPassword.Title"));
			dGetNewPassword.setLocationRelativeTo(this);
			SwingHelper.showAndWait(dGetNewPassword);

			char[] password = dGetNewPassword.getPassword();
			if (password == null)
			{
				return false;
			}

			String basename = null;
			if (certs.length > 0 && certs[0] instanceof X509Certificate)
			{
				basename = X509CertUtil.getCertificateAlias((X509Certificate) certs[0]);
			}
			if (basename == null || basename.isEmpty())
			{
				basename = sEntryAlias;
			}

			// Let the user choose the PEM export file
			fExportFile = chooseExportPEMFile(basename);
			if (fExportFile == null)
			{
				return false;
			}

			if (!confirmOverwrite(fExportFile, getTitle()))
			{
				return false;
			}

			// Do the export

			try (JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(fExportFile)))
			{
				if (password.length == 0)
				{
					pw.writeObject(privKey);
				}
				else
				{
					// TODO: make algorithm configurable/ask user?
					String algorithm = "DES-EDE3-CBC";
					SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
					PEMEncryptor encryptor =
					    new JcePEMEncryptorBuilder(algorithm).setSecureRandom(rand).build(password);
					pw.writeObject(privKey, encryptor);
				}

				for (Certificate cert : certs)
				{
					pw.writeObject(cert);
				}
			}

			m_lastDir.updateLastDir(fExportFile);

			return true;
		}
		catch (FileNotFoundException ex)
		{
			String sMessage =
			    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
			JOptionPane.showMessageDialog(this, sMessage, getTitle(), JOptionPane.WARNING_MESSAGE);
			return false;
		}
		catch (GeneralSecurityException | IOException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}
	}

	/**
	 * Export the private key and certificates of the keystore entry to a PKCS #12 keystore file.
	 *
	 * @param sEntryAlias Entry alias
	 * @return True if the export is successful, false otherwise
	 */
	private boolean exportPrivKeyCertChainPKCS12(String sEntryAlias)
	{
		KeyStore keyStore = m_keyStoreWrap.getKeyStore();

		// Get the entry's password (we may already know it from the wrapper)
		char[] cPassword = m_keyStoreWrap.getEntryPassword(sEntryAlias);

		if (cPassword == null)
		{
			cPassword = KeyStoreUtil.DUMMY_PASSWORD;

			if (m_keyStoreWrap.getKeyStoreType().isEntryPasswordSupported())
			{
				DGetPassword dGetPassword = new DGetPassword(this, RB.getString("FPortecle.KeyEntryPassword.Title"));
				dGetPassword.setLocationRelativeTo(this);
				SwingHelper.showAndWait(dGetPassword);
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

			// Update the keystore wrapper
			m_keyStoreWrap.setEntryPassword(sEntryAlias, cPassword);

			// Create a new PKCS #12 keystore
			KeyStore pkcs12 = KeyStoreUtil.createKeyStore(KeyStoreType.PKCS12);

			// Place the private key and certificate chain into the PKCS #12 keystore under the same alias as
			// it has in the loaded keystore
			pkcs12.setKeyEntry(sEntryAlias, privKey, new char[0], certs);

			// Get a new password for the PKCS #12 keystore
			DGetNewPassword dGetNewPassword = new DGetNewPassword(this, RB.getString("FPortecle.Pkcs12Password.Title"));
			dGetNewPassword.setLocationRelativeTo(this);
			SwingHelper.showAndWait(dGetNewPassword);

			char[] cPKCS12Password = dGetNewPassword.getPassword();

			if (cPKCS12Password == null)
			{
				return false;
			}

			String basename = null;
			if (certs.length > 0 && certs[0] instanceof X509Certificate)
			{
				basename = X509CertUtil.getCertificateAlias((X509Certificate) certs[0]);
			}
			if (basename == null || basename.isEmpty())
			{
				basename = sEntryAlias;
			}

			// Let the user choose the export PKCS #12 file
			fExportFile = chooseExportPKCS12File(basename);
			if (fExportFile == null)
			{
				return false;
			}

			if (!confirmOverwrite(fExportFile, getTitle()))
			{
				return false;
			}

			// Store the keystore to disk
			KeyStoreUtil.saveKeyStore(pkcs12, fExportFile, cPKCS12Password);

			m_lastDir.updateLastDir(fExportFile);

			return true;
		}
		catch (FileNotFoundException ex)
		{
			String sMessage =
			    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
			JOptionPane.showMessageDialog(this, sMessage, getTitle(), JOptionPane.WARNING_MESSAGE);
			return false;
		}
		catch (CryptoException | GeneralSecurityException | IOException ex)
		{
			DThrowable.showAndWait(this, null, ex);
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
		if (fLastDir != null)
		{
			chooser.setCurrentDirectory(fLastDir);
		}

		chooser.setDialogTitle(RB.getString("FPortecle.ExportCertificate.Title"));
		chooser.setMultiSelectionEnabled(false);

		int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.Export.button"));
		if (iRtnValue == JFileChooser.APPROVE_OPTION)
		{
			return chooser.getSelectedFile();
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
		if (fLastDir != null)
		{
			chooser.setCurrentDirectory(fLastDir);
		}

		chooser.setDialogTitle(RB.getString("FPortecle.ExportCertificates.Title"));
		chooser.setMultiSelectionEnabled(false);

		int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.Export.button"));
		if (iRtnValue == JFileChooser.APPROVE_OPTION)
		{
			return chooser.getSelectedFile();
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
		if (fLastDir != null)
		{
			chooser.setCurrentDirectory(fLastDir);
		}

		chooser.setDialogTitle(RB.getString("FPortecle.ExportCertificates.Title"));
		chooser.setMultiSelectionEnabled(false);

		int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.Export.button"));
		if (iRtnValue == JFileChooser.APPROVE_OPTION)
		{
			return chooser.getSelectedFile();
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
		if (fLastDir != null)
		{
			chooser.setCurrentDirectory(fLastDir);
		}

		chooser.setDialogTitle(RB.getString("FPortecle.ExportKeyCertificates.Title"));
		chooser.setMultiSelectionEnabled(false);

		int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.Export.button"));
		if (iRtnValue == JFileChooser.APPROVE_OPTION)
		{
			return chooser.getSelectedFile();
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
		if (fLastDir != null)
		{
			chooser.setCurrentDirectory(fLastDir);
		}

		chooser.setDialogTitle(RB.getString("FPortecle.ExportKeyCertificates.Title"));
		chooser.setMultiSelectionEnabled(false);

		int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.Export.button"));
		if (iRtnValue == JFileChooser.APPROVE_OPTION)
		{
			return chooser.getSelectedFile();
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

		// Not valid for a key-only or a trusted certificate entry
		if (!KeyStoreTableModel.KEY_PAIR_ENTRY.equals(m_jtKeyStore.getSelectedType()))
		{
			return false;
		}

		String sAlias = m_jtKeyStore.getSelectedAlias();
		KeyStore keyStore = m_keyStoreWrap.getKeyStore();

		File fCsrFile = null;

		try
		{
			// Get the entry's password (we may already know it from the wrapper)
			char[] cPassword = m_keyStoreWrap.getEntryPassword(sAlias);

			if (cPassword == null)
			{
				cPassword = KeyStoreUtil.DUMMY_PASSWORD;

				if (m_keyStoreWrap.getKeyStoreType().isEntryPasswordSupported())
				{
					DGetPassword dGetPassword =
					    new DGetPassword(this, RB.getString("FPortecle.KeyEntryPassword.Title"));
					dGetPassword.setLocationRelativeTo(this);
					SwingHelper.showAndWait(dGetPassword);
					cPassword = dGetPassword.getPassword();

					if (cPassword == null)
					{
						return false;
					}
				}
			}

			// Get the key pair entry's private key using the password
			PrivateKey privKey = (PrivateKey) keyStore.getKey(sAlias, cPassword);

			// Update the keystore wrapper
			m_keyStoreWrap.setEntryPassword(sAlias, cPassword);

			// Get the first certificate in the entry's certificate chain
			X509Certificate cert = X509CertUtil.orderX509CertChain(
			    X509CertUtil.convertCertificates(keyStore.getCertificateChain(sAlias)))[0];

			// Let the user choose the file to write the CSR to
			fCsrFile = chooseGenerateCsrFile(X509CertUtil.getCertificateAlias(cert));
			if (fCsrFile == null)
			{
				return false;
			}

			if (!confirmOverwrite(fCsrFile, RB.getString("FPortecle.GenerateCsr.Title")))
			{
				return false;
			}

			// Generate CSR and write it out to file
			try (JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(fCsrFile)))
			{
				pw.writeObject(X509CertUtil.generatePKCS10CSR(cert, privKey));
			}

			// Display success message
			JOptionPane.showMessageDialog(this, RB.getString("FPortecle.CsrGenerationSuccessful.message"),
			    RB.getString("FPortecle.GenerateCsr.Title"), JOptionPane.INFORMATION_MESSAGE);

			m_lastDir.updateLastDir(fCsrFile);

			return true;
		}
		catch (FileNotFoundException ex)
		{
			JOptionPane.showMessageDialog(this,
			    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fCsrFile),
			    RB.getString("FPortecle.GenerateCsr.Title"), JOptionPane.WARNING_MESSAGE);
			return false;
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
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

		// Not valid for a PrivateKey-only entry - the KeyStore API won't allow us to store a PrivateKey
		// without associated certificate chain.
		// TODO: Maybe it'd work for other Key types? Need testing material.
		if (!KeyStoreTableModel.KEY_PAIR_ENTRY.equals(m_jtKeyStore.getSelectedType()))
		{
			return false;
		}

		String sAlias = m_jtKeyStore.getSelectedAlias();
		KeyStore keyStore = m_keyStoreWrap.getKeyStore();
		KeyStoreType ksType = m_keyStoreWrap.getKeyStoreType();

		try
		{
			// Get the entry's password (we may already know it from the wrapper)
			char[] cPassword = m_keyStoreWrap.getEntryPassword(sAlias);

			if (cPassword == null)
			{
				cPassword = KeyStoreUtil.DUMMY_PASSWORD;

				if (ksType.isEntryPasswordSupported())
				{
					DGetPassword dGetPassword =
					    new DGetPassword(this, RB.getString("FPortecle.KeyEntryPassword.Title"));
					dGetPassword.setLocationRelativeTo(this);
					SwingHelper.showAndWait(dGetPassword);
					cPassword = dGetPassword.getPassword();

					if (cPassword == null)
					{
						return false;
					}
				}
			}

			// Update the keystore wrapper
			m_keyStoreWrap.setEntryPassword(sAlias, cPassword);

			sAlias = getNewEntryAlias(keyStore, sAlias, "FPortecle.ClonedKeyPairEntryAlias.Title", true);
			if (sAlias == null)
			{
				return false;
			}

			// Get key and certificates from entry
			Key key = keyStore.getKey(sAlias, cPassword);
			Certificate[] certs = keyStore.getCertificateChain(sAlias);

			// Get a password for the new keystore entry if applicable
			char[] cNewPassword = KeyStoreUtil.DUMMY_PASSWORD;

			if (ksType.isEntryPasswordSupported())
			{
				DGetNewPassword dGetNewPassword =
				    new DGetNewPassword(this, RB.getString("FPortecle.ClonedKeyPairEntryPassword.Title"));
				dGetNewPassword.setLocationRelativeTo(this);
				SwingHelper.showAndWait(dGetNewPassword);
				cNewPassword = dGetNewPassword.getPassword();

				if (cNewPassword == null)
				{
					return false;
				}
			}

			// Delete old entry first
			if (keyStore.containsAlias(sAlias))
			{
				keyStore.deleteEntry(sAlias);
			}

			// Create new entry
			keyStore.setKeyEntry(sAlias, key, cNewPassword, certs);

			// Update the keystore wrapper
			m_keyStoreWrap.setEntryPassword(sAlias, cNewPassword);
			m_keyStoreWrap.setChanged(true);

			// ...and update the frame's components and title
			selectedAlias = sAlias;
			updateControls();
			updateTitle();

			// Display success message
			JOptionPane.showMessageDialog(this, RB.getString("FPortecle.KeyPairCloningSuccessful.message"),
			    RB.getString("FPortecle.CloneKeyPair.Title"), JOptionPane.INFORMATION_MESSAGE);

			return true;
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
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

		// Not valid for non-certificate entries
		if (!KeyStoreTableModel.TRUST_CERT_ENTRY.equals(m_jtKeyStore.getSelectedType()))
		{
			return false;
		}

		String sAlias = m_jtKeyStore.getSelectedAlias();
		KeyStore keyStore = m_keyStoreWrap.getKeyStore();

		try
		{
			// Get the alias of the new entry
			sAlias = getNewEntryAlias(keyStore, sAlias, "FPortecle.ClonedTrustCertEntryAlias.Title", true);
			if (sAlias == null)
			{
				return false;
			}

			// Get certificate from entry
			Certificate cert = keyStore.getCertificate(sAlias);

			// Delete old entry first
			if (keyStore.containsAlias(sAlias))
			{
				keyStore.deleteEntry(sAlias);
			}

			// Create new entry
			keyStore.setCertificateEntry(sAlias, cert);

			// Update the keystore wrapper
			m_keyStoreWrap.setChanged(true);

			// ...and update the frame's components and title
			selectedAlias = sAlias;
			updateControls();
			updateTitle();

			// Display success message
			JOptionPane.showMessageDialog(this, RB.getString("FPortecle.CertificateCloningSuccessful.message"),
			    RB.getString("FPortecle.CloneCertificate.Title"), JOptionPane.INFORMATION_MESSAGE);

			return true;
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}
	}

	/**
	 * Display a report on the currently loaded keystore.
	 *
	 * @return True if the keystore report was displayed successfully, false otherwise
	 */
	private boolean keyStoreReport()
	{
		assert m_keyStoreWrap != null;
		assert m_keyStoreWrap.getKeyStore() != null;

		try
		{
			DKeyStoreReport dKeyStoreReport = new DKeyStoreReport(this, m_keyStoreWrap.getKeyStore());
			dKeyStoreReport.setLocationRelativeTo(this);
			SwingHelper.showAndWait(dKeyStoreReport);
			return true;
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}
	}

	/**
	 * Let the user see the certificate details of the selected keystore entry.
	 *
	 * @return True if the certificate details were viewed successfully, false otherwise
	 */
	private boolean showSelectedEntry()
	{
		assert m_keyStoreWrap != null;
		assert m_keyStoreWrap.getKeyStore() != null;

		// TODO: implement this for key-only entries
		String selectedType = m_jtKeyStore.getSelectedType();
		if (selectedType == null || selectedType.equals(KeyStoreTableModel.KEY_ENTRY))
		{
			return false;
		}

		String sAlias = m_jtKeyStore.getSelectedAlias();
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
			DViewCertificate dViewCertificate = new DViewCertificate(this,
			    MessageFormat.format(RB.getString("FPortecle.CertDetailsEntry.Title"), sAlias), certs);
			dViewCertificate.setLocationRelativeTo(this);
			SwingHelper.showAndWait(dViewCertificate);
			return true;
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
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
		String sAlias = m_jtKeyStore.getSelectedAlias();
		if (sAlias == null)
		{
			return false;
		}

		int iSelected = JOptionPane.showConfirmDialog(this,
		    MessageFormat.format(RB.getString("FPortecle.DeleteEntry.message"), sAlias),
		    RB.getString("FPortecle.DeleteEntry.Title"), JOptionPane.YES_NO_OPTION);
		if (iSelected != JOptionPane.YES_OPTION)
		{
			return false;
		}

		assert m_keyStoreWrap != null;
		assert m_keyStoreWrap.getKeyStore() != null;

		KeyStore keyStore = m_keyStoreWrap.getKeyStore();

		try
		{
			// Delete the entry
			keyStore.deleteEntry(sAlias);

			// Update the keystore wrapper
			m_keyStoreWrap.removeEntryPassword(sAlias);
			m_keyStoreWrap.setChanged(true);
		}
		catch (KeyStoreException ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}

		// Update the frame's components and title
		selectedAlias = null;
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

		if (!m_jtKeyStore.getModel().isCellEditable(iRow, 1))
		{
			return false;
		}

		String sAlias = m_jtKeyStore.getSelectedAlias();

		// Get the new entry alias
		DGetAlias dGetAlias = new DGetAlias(this, RB.getString("FPortecle.NewEntryAlias.Title"), sAlias, true);
		dGetAlias.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dGetAlias);

		return renameEntry(sAlias, dGetAlias.getAlias(), false);
	}

	/**
	 * Let the user rename the selected keystore entry.
	 *
	 * @param oldAlias old entry alias
	 * @param newAlias new entry alias
	 * @param silent if true, attempt to rename to same name will be ignored without popping up an error dialog
	 * @return True if the rename is successful, false otherwise
	 */
	/* package private */boolean renameEntry(String oldAlias, String newAlias, boolean silent)
	{
		if (newAlias == null)
		{
			return false;
		}

		assert m_keyStoreWrap != null;
		assert m_keyStoreWrap.getKeyStore() != null;

		KeyStore keyStore = m_keyStoreWrap.getKeyStore();

		try
		{

			// Check new alias differs from the present one
			if (newAlias.equalsIgnoreCase(oldAlias))
			{
				if (!silent)
				{
					JOptionPane.showMessageDialog(this,
					    MessageFormat.format(RB.getString("FPortecle.RenameAliasIdentical.message"), oldAlias),
					    RB.getString("FPortecle.RenameEntry.Title"), JOptionPane.ERROR_MESSAGE);
				}
				return false;
			}

			// Check entry does not already exist in the keystore
			if (keyStore.containsAlias(newAlias))
			{
				String sMessage = MessageFormat.format(RB.getString("FPortecle.OverWriteEntry.message"), newAlias);

				int iSelected = JOptionPane.showConfirmDialog(this, sMessage,
				    RB.getString("FPortecle.RenameEntry.Title"), JOptionPane.YES_NO_OPTION);
				if (iSelected != JOptionPane.YES_OPTION)
				{
					return false;
				}
			}

			// Create the new entry with the new name and copy the old entry across

			// If the entry is a key pair...
			if (keyStore.isKeyEntry(oldAlias))
			{
				// Get the entry's password (we may already know it from the wrapper)
				char[] cPassword = m_keyStoreWrap.getEntryPassword(oldAlias);

				if (cPassword == null)
				{
					cPassword = KeyStoreUtil.DUMMY_PASSWORD;

					if (m_keyStoreWrap.getKeyStoreType().isEntryPasswordSupported())
					{
						DGetPassword dGetPassword =
						    new DGetPassword(this, RB.getString("FPortecle.KeyEntryPassword.Title"));
						dGetPassword.setLocationRelativeTo(this);
						SwingHelper.showAndWait(dGetPassword);
						cPassword = dGetPassword.getPassword();

						if (cPassword == null)
						{
							return false;
						}
					}
				}

				// Do the copy
				Key key = keyStore.getKey(oldAlias, cPassword);
				Certificate[] certs = keyStore.getCertificateChain(oldAlias);
				keyStore.setKeyEntry(newAlias, key, cPassword, certs);

				// Update the keystore wrapper
				m_keyStoreWrap.setEntryPassword(newAlias, cPassword);
			}
			// ...if the entry is a trusted certificate
			else
			{
				// Do the copy
				Certificate cert = keyStore.getCertificate(oldAlias);
				keyStore.setCertificateEntry(newAlias, cert);
			}

			// Delete the old entry
			keyStore.deleteEntry(oldAlias);

			// Update the keystore wrapper
			m_keyStoreWrap.removeEntryPassword(oldAlias);
			m_keyStoreWrap.setChanged(true);
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
			return false;
		}

		// Update the frame's components and title
		selectedAlias = newAlias;
		updateControls();
		updateTitle();

		return true;
	}

	/**
	 * Update the application's controls dependent on the state of its keystore (e.g. if changes to keystore are saved
	 * disable save tool bar button).
	 */
	private void updateControls()
	{
		// keystore must have been loaded
		assert m_keyStoreWrap != null;
		assert m_keyStoreWrap.getKeyStore() != null;

		m_saveKeyStoreAction.setEnabled(m_keyStoreWrap.isChanged() || m_keyStoreWrap.getKeyStoreFile() == null);
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
		KeyStoreType ksType = m_keyStoreWrap.getKeyStoreType();

		try
		{
			// Update keystore entries table
			((KeyStoreTableModel) m_jtKeyStore.getModel()).load(keyStore);
		}
		catch (KeyStoreException ex)
		{
			DThrowable.showAndWait(this, null, ex);
		}

		// Enable entry password changing only for applicable keystore types
		m_jmiSetKeyPairPass.setEnabled(ksType.isEntryPasswordSupported());

		// Change keystore type menu items dependent on keystore type

		// Enable change keystore type menu
		m_jmChangeKeyStoreType.setEnabled(true);

		// Initially enable the menu items for all available types
		m_jmiChangeKeyStoreTypeJks.setEnabled(KeyStoreUtil.isAvailable(KeyStoreType.JKS));
		m_jmiChangeKeyStoreTypeCaseExactJks.setEnabled(KeyStoreUtil.isAvailable(KeyStoreType.CaseExactJKS));
		m_jmiChangeKeyStoreTypeJceks.setEnabled(KeyStoreUtil.isAvailable(KeyStoreType.JCEKS));
		m_jmiChangeKeyStoreTypePkcs12.setEnabled(true);
		m_jmiChangeKeyStoreTypeBks.setEnabled(true);
		m_jmiChangeKeyStoreTypeBksV1.setEnabled(true);
		m_jmiChangeKeyStoreTypeUber.setEnabled(true);
		m_jmiChangeKeyStoreTypeBcfks.setEnabled(true);
		m_jmiChangeKeyStoreTypeGkr.setEnabled(KeyStoreUtil.isAvailable(KeyStoreType.GKR));

		// Disable the menu item matching current keystore type
		switch (ksType)
		{
			case JKS:
				m_jmiChangeKeyStoreTypeJks.setEnabled(false);
				break;
			case CaseExactJKS:
				m_jmiChangeKeyStoreTypeCaseExactJks.setEnabled(false);
				break;
			case JCEKS:
				m_jmiChangeKeyStoreTypeJceks.setEnabled(false);
				break;
			case PKCS12:
				m_jmiChangeKeyStoreTypePkcs12.setEnabled(false);
				break;
			case BKS:
				m_jmiChangeKeyStoreTypeBks.setEnabled(false);
				break;
			case BKS_V1:
				m_jmiChangeKeyStoreTypeBksV1.setEnabled(false);
				break;
			case UBER:
				m_jmiChangeKeyStoreTypeUber.setEnabled(false);
				break;
			case BCFKS:
				m_jmiChangeKeyStoreTypeBcfks.setEnabled(false);
				break;
			case GKR:
				m_jmiChangeKeyStoreTypeGkr.setEnabled(false);
				break;
			default:
				// Nothing
		}

		m_jtKeyStore.clearSelection();
		if (selectedAlias != null)
		{
			for (int i = 0, len = m_jtKeyStore.getRowCount(); i < len; i++)
			{
				if (selectedAlias.equals(m_jtKeyStore.getValueAt(i, 1)))
				{
					m_jtKeyStore.setRowSelectionInterval(i, i);
					break;
				}
			}
		}
	}

	/**
	 * Update the application's controls dependent on the state of its keystore.
	 */
	private void updateTitle()
	{
		// Application name
		String sAppName = RB.getString("FPortecle.Title");

		// No keystore loaded so just display the application name
		if (m_keyStoreWrap == null)
		{
			setTitle(sAppName);
		}
		else
		{
			File fKeyStore = m_keyStoreWrap.getKeyStoreFile();

			if (fKeyStore == null)
			{
				// A newly created keystore is loaded - display Untitled string and application name
				setTitle(MessageFormat.format("[{0}] - {1}", RB.getString("FPortecle.Untitled"), sAppName));
			}
			else
			{
				// Keystore loaded - display keystore file path, "modified" indicator, and application name
				String modInd = m_keyStoreWrap.isChanged() ? RB.getString("FPortecle.Modified") : "";
				setTitle(MessageFormat.format("{0}{1} - {2}", fKeyStore, modInd, sAppName));
			}
		}
	}

	/**
	 * Display the supplied text in the status bar.
	 *
	 * @param sStatus Text to display
	 */
	@Override
	public void setStatusBarText(String sStatus)
	{
		m_jlStatusBar.setText(sStatus);
	}

	/**
	 * Set the text in the staus bar to reflect the status of the currently loaded keystore.
	 */
	@Override
	public void setDefaultStatusBarText()
	{
		// No keystore loaded...
		if (m_keyStoreWrap == null)
		{
			setStatusBarText(RB.getString("FPortecle.noKeyStore.statusbar"));
		}
		// keystore loaded...
		else
		{
			// Get the keystore and display information on its type and size
			KeyStore ksLoaded = m_keyStoreWrap.getKeyStore();

			int iSize;
			try
			{
				iSize = ksLoaded.size();
			}
			catch (KeyStoreException ex)
			{
				setStatusBarText("");
				DThrowable.showAndWait(this, null, ex);
				return;
			}

			String sType = KeyStoreType.valueOfType(ksLoaded.getType()).toString();
			String sProv = ksLoaded.getProvider().getName();

			if (iSize == 1)
			{
				setStatusBarText(MessageFormat.format(RB.getString("FPortecle.entry.statusbar"), sType, sProv));
			}
			else
			{
				setStatusBarText(
				    MessageFormat.format(RB.getString("FPortecle.entries.statusbar"), sType, sProv, iSize));
			}
		}
	}

	/**
	 * Save the application preferences.
	 */
	private void saveAppPrefs()
	{
		try
		{
			// The size of the keystore table panel - determines the size of the main frame
			PREFS.putInt(RB.getString("AppPrefs.TableWidth"), m_jpKeyStoreTable.getWidth());
			PREFS.putInt(RB.getString("AppPrefs.TableHeight"), m_jpKeyStoreTable.getHeight());

			// The size of the keystore table's alias column - determines the size of all of the table's
			// columns
			PREFS.putInt(RB.getString("AppPrefs.AliasWidth"), m_jtKeyStore.getColumnModel().getColumn(1).getWidth());

			// Application's position on the desktop
			PREFS.putInt(RB.getString("AppPrefs.XPos"), this.getX());
			PREFS.putInt(RB.getString("AppPrefs.YPos"), this.getY());

			// Use CA certificates file?
			PREFS.putBoolean(RB.getString("AppPrefs.UseCaCerts"), m_bUseCaCerts);

			// CA Certificates file
			PREFS.put(RB.getString("AppPrefs.CaCertsFile"), m_fCaCertsFile.toString());

			// Recent files
			File[] fRecentFiles = m_jmrfFile.getRecentFiles();
			for (int iCnt = 0; iCnt < fRecentFiles.length; iCnt++)
			{
				PREFS.put(RB.getString("AppPrefs.RecentFile") + (iCnt + 1), fRecentFiles[iCnt].toString());
			}

			// Look & feel
			LookAndFeel currentLookAndFeel = UIManager.getLookAndFeel();

			if (lookFeelClassName != null)
			{
				// Setting made in options
				PREFS.put(RB.getString("AppPrefs.LookFeel"), lookFeelClassName);
			}
			else
			{
				// Current setting
				if (currentLookAndFeel != null)
				{
					UIManager.LookAndFeelInfo[] lookFeelInfos = UIManager.getInstalledLookAndFeels();

					for (UIManager.LookAndFeelInfo lookFeelInfo : lookFeelInfos)
					{
						// Store current look & feel class name
						if (currentLookAndFeel.getName().equals(lookFeelInfo.getName()))
						{
							PREFS.put(RB.getString("AppPrefs.LookFeel"), lookFeelInfo.getClassName());
							break;
						}
					}
				}
			}

			// Use Look & Feel's decoration?
			if (m_bLookFeelDecorationOptions != null)
			{
				// Setting made in options
				PREFS.putBoolean(RB.getString("AppPrefs.LookFeelDecor"), m_bLookFeelDecorationOptions);
			}
			else
			{
				// Current setting
				PREFS.putBoolean(RB.getString("AppPrefs.LookFeelDecor"), JFrame.isDefaultLookAndFeelDecorated());
			}
			
			if (m_bBouncyCastleAllowUnsafeInteger != null)
			{
				// Setting made in options
				PREFS.putBoolean(RB.getString("AppPrefs.BouncyCastleAllowUnsafeInteger"), m_bBouncyCastleAllowUnsafeInteger);
			}

			PREFS.sync();
		}
		catch (Exception ex)
		{
			DThrowable.showAndWait(this, null, ex);
		}
	}

	/**
	 * Exit the application.
	 */
	private void exitApplication()
	{
		// Does the current keystore contain unsaved changes?
		if (needSave())
		{
			// Yes - ask the user if it should be saved
			switch (wantSave())
			{
				case JOptionPane.YES_OPTION:
					// Save it
					saveKeyStore();
					break;
				case JOptionPane.CANCEL_OPTION:
					return;
			}
		}

		// Save application preferences
		saveAppPrefs();

		System.exit(0);
	}

	/**
	 * Initialize the application's look and feel.
	 */
	private static void initLookAndFeel()
	{
		try
		{
			// Use the look and feel
			UIManager.setLookAndFeel(PREFS.get(RB.getString("AppPrefs.LookFeel"), FPortecle.DEFAULT_LOOK_FEEL));
		}
		// Didn't work - no matter
		catch (ClassNotFoundException | IllegalAccessException | InstantiationException
		    | UnsupportedLookAndFeelException e)
		{
			// Ignored
		}

		// Use look & feel's decoration?
		boolean bLookFeelDecorated = PREFS.getBoolean(RB.getString("AppPrefs.LookFeelDecor"), false);

		JFrame.setDefaultLookAndFeelDecorated(bLookFeelDecorated);
		JDialog.setDefaultLookAndFeelDecorated(bLookFeelDecorated);
	}

	/**
	 * Set cursor to busy and disable application input. This can be reversed by a subsequent call to setCursorFree.
	 */
	private void setCursorBusy()
	{
		// Block all mouse events using glass pane
		Component glassPane = getRootPane().getGlassPane();
		glassPane.addMouseListener(new MouseAdapter()
		{
			// Nothing
		});
		glassPane.setVisible(true);

		// Set cursor to busy
		glassPane.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
	}

	/**
	 * Set cursor to free and enable application input. Called after a call to setCursorBusy.
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
		return Toolkit.getDefaultToolkit().createImage(FPortecle.class.getResource(RB.getString(key)));
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
		if (file.isFile())
		{
			String sMessage = MessageFormat.format(RB.getString("FPortecle.OverWriteFile.message"), file.getName());
			int iSelected = JOptionPane.showConfirmDialog(this, sMessage, title, JOptionPane.YES_NO_OPTION);
			return iSelected == JOptionPane.YES_OPTION;
		}
		return true;
	}

	/**
	 * Gets a new entry alias from user, handling overwrite issues.
	 *
	 * @param keyStore target keystore
	 * @param sAlias suggested alias
	 * @param dialogTitleKey message key for dialog titles
	 * @param selectAlias whether to pre-select alias text in text field
	 * @return alias for new entry, null if user cancels the operation
	 * @throws KeyStoreException
	 */
	private String getNewEntryAlias(KeyStore keyStore, String sAlias, String dialogTitleKey, boolean selectAlias)
	    throws KeyStoreException
	{
		while (true)
		{
			// Get the alias for the new entry
			DGetAlias dGetAlias = new DGetAlias(this, RB.getString(dialogTitleKey), sAlias.toLowerCase(), selectAlias);
			dGetAlias.setLocationRelativeTo(this);
			SwingHelper.showAndWait(dGetAlias);

			sAlias = dGetAlias.getAlias();
			if (sAlias == null)
			{
				return null;
			}

			// Check an entry with the selected does not already exist in the keystore
			if (!keyStore.containsAlias(sAlias))
			{
				return sAlias;
			}

			String sMessage = MessageFormat.format(RB.getString("FPortecle.OverWriteEntry.message"), sAlias);

			int iSelected = JOptionPane.showConfirmDialog(this, sMessage, RB.getString(dialogTitleKey),
			    JOptionPane.YES_NO_CANCEL_OPTION);
			switch (iSelected)
			{
				case JOptionPane.YES_OPTION:
					return sAlias;
				case JOptionPane.NO_OPTION:
					// keep looping
					break;
				default:
					return null;
			}
		}
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
			putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(
			    RB.getString("FPortecle.NewKeyStoreAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
			putValue(LONG_DESCRIPTION, RB.getString("FPortecle.NewKeyStoreAction.statusbar"));
			putValue(MNEMONIC_KEY, Integer.valueOf(RB.getString("FPortecle.NewKeyStoreAction.mnemonic").charAt(0)));
			putValue(NAME, RB.getString("FPortecle.NewKeyStoreAction.text"));
			putValue(SHORT_DESCRIPTION, RB.getString("FPortecle.NewKeyStoreAction.tooltip"));
			putValue(SMALL_ICON, new ImageIcon(getResImage("FPortecle.NewKeyStoreAction.image")));
			setEnabled(true);
		}

		/**
		 * Perform action.
		 */
		@Override
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
			putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(
			    RB.getString("FPortecle.SaveKeyStoreAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
			putValue(LONG_DESCRIPTION, RB.getString("FPortecle.SaveKeyStoreAction.statusbar"));
			putValue(MNEMONIC_KEY, Integer.valueOf(RB.getString("FPortecle.SaveKeyStoreAction.mnemonic").charAt(0)));
			putValue(NAME, RB.getString("FPortecle.SaveKeyStoreAction.text"));
			putValue(SHORT_DESCRIPTION, RB.getString("FPortecle.SaveKeyStoreAction.tooltip"));
			putValue(SMALL_ICON, new ImageIcon(getResImage("FPortecle.SaveKeyStoreAction.image")));
			setEnabled(false);
		}

		/**
		 * Perform action.
		 */
		@Override
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
			putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(
			    RB.getString("FPortecle.OpenKeyStoreFileAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
			putValue(LONG_DESCRIPTION, RB.getString("FPortecle.OpenKeyStoreFileAction.statusbar"));
			putValue(MNEMONIC_KEY,
			    Integer.valueOf(RB.getString("FPortecle.OpenKeyStoreFileAction.mnemonic").charAt(0)));
			putValue(NAME, RB.getString("FPortecle.OpenKeyStoreFileAction.text"));
			putValue(SHORT_DESCRIPTION, RB.getString("FPortecle.OpenKeyStoreFileAction.tooltip"));
			putValue(SMALL_ICON, new ImageIcon(getResImage("FPortecle.OpenKeyStoreFileAction.image")));
			setEnabled(true);
		}

		/**
		 * Perform action.
		 */
		@Override
		public void act()
		{
			openKeyStoreFile();
		}
	}

	/**
	 * Action to open a keystore file.
	 */
	private class OpenCaCertsKeyStoreAction
	    extends AbstractAction
	{
		/**
		 * Construct action.
		 */
		public OpenCaCertsKeyStoreAction()
		{
			putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(
			    RB.getString("FPortecle.OpenCaCertsKeyStoreAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
			putValue(LONG_DESCRIPTION, RB.getString("FPortecle.OpenCaCertsKeyStoreAction.statusbar"));
			putValue(MNEMONIC_KEY,
			    Integer.valueOf(RB.getString("FPortecle.OpenCaCertsKeyStoreAction.mnemonic").charAt(0)));
			putValue(NAME, RB.getString("FPortecle.OpenCaCertsKeyStoreAction.text"));
			putValue(SHORT_DESCRIPTION, RB.getString("FPortecle.OpenCaCertsKeyStoreAction.tooltip"));
			putValue(SMALL_ICON, new ImageIcon(getResImage("FPortecle.OpenCaCertsKeyStoreAction.image")));
			setEnabled(true);
		}

		/**
		 * Perform action.
		 */
		@Override
		public void act()
		{
			openCaCertsKeyStoreFile();
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
			putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(
			    RB.getString("FPortecle.GenKeyPairAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
			putValue(LONG_DESCRIPTION, RB.getString("FPortecle.GenKeyPairAction.statusbar"));
			putValue(MNEMONIC_KEY, Integer.valueOf(RB.getString("FPortecle.GenKeyPairAction.mnemonic").charAt(0)));
			putValue(NAME, RB.getString("FPortecle.GenKeyPairAction.text"));
			putValue(SHORT_DESCRIPTION, RB.getString("FPortecle.GenKeyPairAction.tooltip"));
			putValue(SMALL_ICON, new ImageIcon(getResImage("FPortecle.GenKeyPairAction.image")));
			setEnabled(false);
		}

		/**
		 * Perform action.
		 */
		@Override
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
			putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(
			    RB.getString("FPortecle.ImportTrustCertAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
			putValue(LONG_DESCRIPTION, RB.getString("FPortecle.ImportTrustCertAction.statusbar"));
			putValue(MNEMONIC_KEY, Integer.valueOf(RB.getString("FPortecle.ImportTrustCertAction.mnemonic").charAt(0)));
			putValue(NAME, RB.getString("FPortecle.ImportTrustCertAction.text"));
			putValue(SHORT_DESCRIPTION, RB.getString("FPortecle.ImportTrustCertAction.tooltip"));
			putValue(SMALL_ICON, new ImageIcon(getResImage("FPortecle.ImportTrustCertAction.image")));
			setEnabled(false);
		}

		/**
		 * Perform action.
		 */
		@Override
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
			putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(
			    RB.getString("FPortecle.ImportKeyPairAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
			putValue(LONG_DESCRIPTION, RB.getString("FPortecle.ImportKeyPairAction.statusbar"));
			putValue(MNEMONIC_KEY, Integer.valueOf(RB.getString("FPortecle.ImportKeyPairAction.mnemonic").charAt(0)));
			putValue(NAME, RB.getString("FPortecle.ImportKeyPairAction.text"));
			putValue(SHORT_DESCRIPTION, RB.getString("FPortecle.ImportKeyPairAction.tooltip"));
			putValue(SMALL_ICON, new ImageIcon(getResImage("FPortecle.ImportKeyPairAction.image")));
			setEnabled(false);
		}

		/**
		 * Perform action.
		 */
		@Override
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
			putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(
			    RB.getString("FPortecle.SetKeyStorePassAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
			putValue(LONG_DESCRIPTION, RB.getString("FPortecle.SetKeyStorePassAction.statusbar"));
			putValue(MNEMONIC_KEY, Integer.valueOf(RB.getString("FPortecle.SetKeyStorePassAction.mnemonic").charAt(0)));
			putValue(NAME, RB.getString("FPortecle.SetKeyStorePassAction.text"));
			putValue(SHORT_DESCRIPTION, RB.getString("FPortecle.SetKeyStorePassAction.tooltip"));
			putValue(SMALL_ICON, new ImageIcon(getResImage("FPortecle.SetKeyStorePassAction.image")));
			setEnabled(false);
		}

		/**
		 * Perform action.
		 */
		@Override
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
			putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(
			    RB.getString("FPortecle.KeyStoreReportAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
			putValue(LONG_DESCRIPTION, RB.getString("FPortecle.KeyStoreReportAction.statusbar"));
			putValue(MNEMONIC_KEY, Integer.valueOf(RB.getString("FPortecle.KeyStoreReportAction.mnemonic").charAt(0)));
			putValue(NAME, RB.getString("FPortecle.KeyStoreReportAction.text"));
			putValue(SHORT_DESCRIPTION, RB.getString("FPortecle.KeyStoreReportAction.tooltip"));
			putValue(SMALL_ICON, new ImageIcon(getResImage("FPortecle.KeyStoreReportAction.image")));
			setEnabled(false);
		}

		/**
		 * Perform action.
		 */
		@Override
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
			putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(
			    RB.getString("FPortecle.ExamineCertAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
			putValue(LONG_DESCRIPTION, RB.getString("FPortecle.ExamineCertAction.statusbar"));
			putValue(MNEMONIC_KEY, Integer.valueOf(RB.getString("FPortecle.ExamineCertAction.mnemonic").charAt(0)));
			putValue(NAME, RB.getString("FPortecle.ExamineCertAction.text"));
			putValue(SHORT_DESCRIPTION, RB.getString("FPortecle.ExamineCertAction.tooltip"));
			putValue(SMALL_ICON, new ImageIcon(getResImage("FPortecle.ExamineCertAction.image")));
			setEnabled(true);
		}

		/**
		 * Perform action.
		 */
		@Override
		public void act()
		{
			examineCert(null);
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
			putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(
			    RB.getString("FPortecle.ExamineCertSSLAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
			putValue(LONG_DESCRIPTION, RB.getString("FPortecle.ExamineCertSSLAction.statusbar"));
			putValue(MNEMONIC_KEY, Integer.valueOf(RB.getString("FPortecle.ExamineCertSSLAction.mnemonic").charAt(0)));
			putValue(NAME, RB.getString("FPortecle.ExamineCertSSLAction.text"));
			putValue(SHORT_DESCRIPTION, RB.getString("FPortecle.ExamineCertSSLAction.tooltip"));
			putValue(SMALL_ICON, new ImageIcon(getResImage("FPortecle.ExamineCertSSLAction.image")));
			setEnabled(true);
		}

		/**
		 * Perform action.
		 */
		@Override
		public void act()
		{
			examineCertSSL(null);
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
			putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(
			    RB.getString("FPortecle.ExamineCsrAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
			putValue(LONG_DESCRIPTION, RB.getString("FPortecle.ExamineCsrAction.statusbar"));
			putValue(MNEMONIC_KEY, Integer.valueOf(RB.getString("FPortecle.ExamineCsrAction.mnemonic").charAt(0)));
			putValue(NAME, RB.getString("FPortecle.ExamineCsrAction.text"));
			putValue(SHORT_DESCRIPTION, RB.getString("FPortecle.ExamineCsrAction.tooltip"));
			putValue(SMALL_ICON, new ImageIcon(getResImage("FPortecle.ExamineCsrAction.image")));
			setEnabled(true);
		}

		/**
		 * Perform action.
		 */
		@Override
		public void act()
		{
			examineCSR(null);
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
			putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(
			    RB.getString("FPortecle.ExamineCrlAction.accelerator").charAt(0), InputEvent.CTRL_MASK));
			putValue(LONG_DESCRIPTION, RB.getString("FPortecle.ExamineCrlAction.statusbar"));
			putValue(MNEMONIC_KEY, Integer.valueOf(RB.getString("FPortecle.ExamineCrlAction.mnemonic").charAt(0)));
			putValue(NAME, RB.getString("FPortecle.ExamineCrlAction.text"));
			putValue(SHORT_DESCRIPTION, RB.getString("FPortecle.ExamineCrlAction.tooltip"));
			putValue(SMALL_ICON, new ImageIcon(getResImage("FPortecle.ExamineCrlAction.image")));
			setEnabled(true);
		}

		/**
		 * Perform action.
		 */
		@Override
		public void act()
		{
			examineCRL(null);
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
			putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(KeyEvent.VK_F1, 0));
			putValue(LONG_DESCRIPTION, RB.getString("FPortecle.HelpAction.statusbar"));
			putValue(MNEMONIC_KEY, Integer.valueOf(RB.getString("FPortecle.HelpAction.mnemonic").charAt(0)));
			putValue(NAME, RB.getString("FPortecle.HelpAction.text"));
			putValue(SHORT_DESCRIPTION, RB.getString("FPortecle.HelpAction.tooltip"));
			putValue(SMALL_ICON, new ImageIcon(getResImage("FPortecle.HelpAction.image")));
			setEnabled(true);
		}

		/**
		 * Perform action.
		 */
		@Override
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

		@Override
		public void actionPerformed(ActionEvent evt)
		{
			setDefaultStatusBarText();
			setCursorBusy();
			repaint();
			try
			{
				act();
			}
			finally
			{
				setCursorFree();
			}
		}
	}

	/**
	 * ActionListener helper class.
	 */
	private abstract class ActionListener
	    implements java.awt.event.ActionListener
	{
		protected abstract void act();

		@Override
		public void actionPerformed(ActionEvent evt)
		{
			setDefaultStatusBarText();
			setCursorBusy();
			repaint();
			try
			{
				act();
			}
			finally
			{
				setCursorFree();
			}
		}
	}

	private class KeyStoreTable
	    extends JTable
	{
		private KeyStoreTable(KeyStoreTableModel model)
		{
			super(model);

			getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

			// Install listener to keep track of last selected alias
			getSelectionModel().addListSelectionListener(new ListSelectionListener()
			{
				@Override
				public void valueChanged(ListSelectionEvent e)
				{
					if (!e.getValueIsAdjusting())
					{
						String alias = getSelectedAlias();
						if (alias != null)
						{
							selectedAlias = alias;
						}
					}
				}
			});
			setTransferHandler(new FileTransferHander());
		}

		private String getSelectedType()
		{
			int selectedRow = getSelectedRow();
			return (selectedRow >= 0) ? (String) getValueAt(selectedRow, 0) : null;
		}

		private String getSelectedAlias()
		{
			int selectedRow = getSelectedRow();
			return (selectedRow >= 0) ? (String) getValueAt(selectedRow, 1) : null;
		}

		private class FileTransferHander
		    extends SingleFileDropHelper
		{
			@Override
			public boolean canImport(TransferSupport support)
			{
				if (super.canImport(support))
				{
					m_lastDir.updateLastDir(file);
					return true;
				}
				return false;
			}

			@Override
			public boolean importData(JComponent comp, Transferable t)
			{
				if (file != null)
				{
					// Will refactor this later, taken from openKeystore();
					// Does the current keystore contain unsaved changes?
					if (needSave())
					{
						// Yes - ask the user if it should be saved
						int iWantSave = wantSave();

						if ((iWantSave == JOptionPane.YES_OPTION && !saveKeyStore()) ||
						    iWantSave == JOptionPane.CANCEL_OPTION)
						{
							return false;
						}
					}
					return openFile(file);
				}
				return false;
			}
		}
	}

	/**
	 * Method to determine and open generic files dropped into Portecle.
	 *
	 * @param file the file to open
	 * @return true if the file can be opened, false otherwise
	 */
	private boolean openFile(File file)
	{
		if (file != null)
		{
			String fileName = file.getName().toLowerCase(Locale.ENGLISH);
			for (String ext : FileChooserFactory.CERT_EXTS)
			{
				if (fileName.endsWith("." + ext))
				{
					examineCert(file);
					return true;
				}
			}
			for (String ext : FileChooserFactory.CRL_EXTS)
			{
				if (fileName.endsWith("." + ext))
				{
					examineCRL(file);
					return true;
				}
			}
			for (String ext : FileChooserFactory.CSR_EXTS)
			{
				if (fileName.endsWith("." + ext))
				{
					examineCSR(file);
					return true;
				}
			}
			return openKeyStoreFile(file, true);
		}
		return false;
	}

	/**
	 * Runnable to create and show Portecle GUI.
	 */
	private static class CreateAndShowGui
	    implements Runnable
	{

		/** File or host:port to open initially */
		private final Object m_obj;

		/**
		 * Construct CreateAndShowGui.
		 *
		 * @param obj File or host:port to open initially (supply null if none)
		 */
		public CreateAndShowGui(Object obj)
		{
			m_obj = obj;
		}

		/**
		 * Create and show Portecle GUI.
		 */
		@Override
		public void run()
		{
			initLookAndFeel();
			FPortecle fPortecle = new FPortecle();
			fPortecle.setVisible(true);
			if (m_obj instanceof File)
			{
				fPortecle.openFile((File) m_obj);
			}
			else if (m_obj instanceof InetSocketAddress)
			{
				fPortecle.examineCertSSL((InetSocketAddress) m_obj);
			}
		}
	}

	/**
	 * Start the Portecle application. Takes one optional argument - the location of a keystore file to open upon
	 * startup.
	 *
	 * @param args the command line arguments
	 */
	public static void main(String[] args)
	{
		// Make Metal theme use non-bold fonts (see javax.swing.plaf.metal.MetalLookAndFeel javadoc)
		UIManager.put("swing.boldMetal", Boolean.FALSE);

		try
		{
			Provider bcProv = Security.getProvider("BC");

			if (bcProv == null)
			{
				// Instantiate the Bouncy Castle provider
				Class<?> bcProvClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
				bcProv = (Provider) bcProvClass.newInstance();

				// Add BC as a security provider
				Security.addProvider(bcProv);
			}

			// Check BC version
			Double bcVer = bcProv.getVersion();
			if (REQ_BC_VERSION.compareTo(bcVer) > 0)
			{
				JOptionPane.showMessageDialog(new JFrame(),
				    MessageFormat.format(RB.getString("FPortecle.NoBcVersion.message"), REQ_BC_VERSION, bcVer),
				    RB.getString("FPortecle.Title"), JOptionPane.WARNING_MESSAGE);
			}
		}
		catch (Throwable thw)
		{
			// No sign of the provider - warn the user and exit
			LOG.log(Level.SEVERE, "FPortecle.NoLoadBc.message", thw);
			JOptionPane.showMessageDialog(new JFrame(), RB.getString("FPortecle.NoLoadBc.message"),
			    RB.getString("FPortecle.Title"), JOptionPane.ERROR_MESSAGE);
			System.exit(1);
		}

		// Install additional providers
		String[] additionalProviders = RB.getString("FPortecle.AdditionalProviders").split("[\\s,]+");
		for (String addProv : additionalProviders)
		{
			String[] prov = addProv.split(":+", 2);
			if (Security.getProvider(prov[0]) == null)
			{
				try
				{
					Class<?> provClass = Class.forName(prov[1]);
					Security.addProvider((Provider) provClass.newInstance());
				}
				catch (Throwable t)
				{
					// TODO: should maybe notify in some cases?
					// E.g. Throwable, but not Exception?
				}
			}
		}

		// If arguments have been supplied, treat the first one that's not "-open" (web start passes that when
		// opening associated files) as a keystore/certificate etc file
		Object toOpen = null;
		for (String arg : args)
		{
			if (!arg.equals("-open"))
			{
				if (arg.matches("^[\\w.]+:\\d+$"))
				{
					String host = arg.substring(0, arg.indexOf(":"));
					int port = Integer.parseInt(arg.substring(arg.indexOf(":") + 1));
					toOpen = new InetSocketAddress(host, port);
				}
				else
				{
					toOpen = new File(arg);
				}
				break;
			}
		}

		// Create and show GUI on the event handler thread
		SwingUtilities.invokeLater(new CreateAndShowGui(toOpen));
	}
}
