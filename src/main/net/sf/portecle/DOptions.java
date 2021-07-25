/*
 * DOptions.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004-2008 Ville Skyttä, ville.skytta@iki.fi
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

import static net.sf.portecle.FPortecle.RB;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.Map;
import java.util.TreeMap;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.LookAndFeel;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;

/**
 * Modal dialog to allow the users to configure Portecle options, CA certificates keystore, and look &amp; feel.
 */
class DOptions
    extends PortecleJDialog
{
	/** Use CA certificates check box */
	private JCheckBox m_jcbUseCaCerts;

	/** CA certificates file text field */
	private JTextField m_jtfCaCertsFile;

	/** Look &amp; feel combo box */
	private JComboBox<String> m_jcbLookFeel;

	/** Look &amp; feel decorated check box */
	private JCheckBox m_jcbLookFeelDecorated;

	/** Use CA certificates keystore file? */
	private boolean m_bUseCaCerts;

	/** Chosen CA certificates keystore file */
	private File m_fCaCertsFile;

	/** Available Look and Feel information - reflects what is in choice box */
	private final TreeMap<String, UIManager.LookAndFeelInfo> lookFeelInfos = new TreeMap<>();

	/** Chosen look &amp; feel information */
	private String lookFeelClassName;

	/** Use look &amp; feel for window decoration? */
	private boolean m_bLookFeelDecorated;
	
	/** Look &amp; feel decorated check box */
	private JCheckBox m_jcbBcAllowUnsafeInteger;

	/** Bouncy Castle Option Allow Unsafe Integer? */
	private boolean m_bBcAllowUnsafeInteger;

	/**
	 * Creates new DOptions dialog.
	 *
	 * @param parent The parent window
	 * @param bUseCaCerts Use CA certificates keystore file?
	 * @param fCaCertsFile CA certificates keystore file
	 * @param bBcAllowUnsafeInteger BC Option AllowUnsafeInteger
	 */
	public DOptions(Window parent, boolean bUseCaCerts, File fCaCertsFile, boolean bBcAllowUnsafeInteger)
	{
		super(parent, true);
		m_bUseCaCerts = bUseCaCerts;
		m_fCaCertsFile = fCaCertsFile;
		m_bBcAllowUnsafeInteger =bBcAllowUnsafeInteger;
		initComponents();
	}

	/**
	 * Initialise the dialog's GUI components.
	 */
	private void initComponents()
	{
		// Setup tabbed panels of options

		// CA certs options tab panel
		m_jcbUseCaCerts = new JCheckBox(RB.getString("DOptions.m_jcbUseCaCerts.text"), m_bUseCaCerts);
		m_jcbUseCaCerts.setToolTipText(RB.getString("DOptions.m_jcbUseCaCerts.tooltip"));

		JPanel jpUseCaCerts = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpUseCaCerts.add(m_jcbUseCaCerts);

		m_jtfCaCertsFile = new JTextField(m_fCaCertsFile.toString(), 20);
		m_jtfCaCertsFile.setToolTipText(RB.getString("DOptions.m_jtfCaCertsFile.tooltip"));
		m_jtfCaCertsFile.setEditable(false);
		JPanel jpCaCertsFile = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpCaCertsFile.add(new JLabel(RB.getString("DOptions.jlCaCertsFile.text")));
		jpCaCertsFile.add(m_jtfCaCertsFile);

		JButton jbBrowseCaCertsFile = new JButton(RB.getString("DOptions.jbBrowseCaCertsFile.text"));
		jbBrowseCaCertsFile.setMnemonic(RB.getString("DOptions.jbBrowseCaCertsFile.mnemonic").charAt(0));
		jbBrowseCaCertsFile.setToolTipText(RB.getString("DOptions.jbBrowseCaCertsFile.tooltip"));
		jbBrowseCaCertsFile.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent evt)
			{
				browsePressed();
			}
		});
		jpCaCertsFile.add(jbBrowseCaCertsFile);

		JButton jbResetCaCertsFile = new JButton(RB.getString("DOptions.jbResetCaCertsFile.text"));
		jbResetCaCertsFile.setMnemonic(RB.getString("DOptions.jbResetCaCertsFile.mnemonic").charAt(0));
		jbResetCaCertsFile.setToolTipText(RB.getString("DOptions.jbResetCaCertsFile.tooltip"));
		jbResetCaCertsFile.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent evt)
			{
				resetPressed();
			}
		});
		jpCaCertsFile.add(jbResetCaCertsFile);

		JPanel jpCaCerts = new JPanel(new GridLayout(2, 1));
		jpCaCerts.add(jpUseCaCerts);
		jpCaCerts.add(jpCaCertsFile);

		// Look & feel tabbed options tab panel

		// Create and populate combo box with available look & feels
		m_jcbLookFeel = new JComboBox<>();
		m_jcbLookFeel.setToolTipText(RB.getString("DOptions.m_jcbLookFeel.tooltip"));

		// Current Look and Feel
		LookAndFeel currentLookAndFeel = UIManager.getLookAndFeel();

		for (UIManager.LookAndFeelInfo lookFeelInfo : UIManager.getInstalledLookAndFeels())
		{
			String name = lookFeelInfo.getName();
			if (lookFeelInfos.containsKey(name))
			{
				continue;
			}

			// Check if it's a supported one (e.g. Windows on Linux is not)
			boolean bSupported = false;
			try
			{
				LookAndFeel laf = (LookAndFeel) Class.forName(lookFeelInfo.getClassName()).newInstance();
				bSupported = laf.isSupportedLookAndFeel();
			}
			catch (Exception e)
			{
				// Ignored
			}
			if (!bSupported)
			{
				continue;
			}

			lookFeelInfos.put(name, lookFeelInfo);
		}

		// Populate combo
		for (Map.Entry<String, UIManager.LookAndFeelInfo> entry : lookFeelInfos.entrySet())
		{
			UIManager.LookAndFeelInfo info = entry.getValue();
			m_jcbLookFeel.addItem(info.getName());

			// Pre-select current look and feel. UIManager.LookAndFeelInfo.getName() and LookAndFeel.getName()
			// can return different strings for the same look and feel, so we compare class names.
			if (currentLookAndFeel != null && currentLookAndFeel.getClass().getName().equals(info.getClassName()))
			{
				m_jcbLookFeel.setSelectedIndex(m_jcbLookFeel.getItemCount() - 1);
			}
		}

		JPanel jpLookFeelControls = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpLookFeelControls.add(new JLabel(RB.getString("DOptions.jlLookFeel.text")));
		jpLookFeelControls.add(m_jcbLookFeel);

		// Create and populate check box with look & feel decorated setting
		m_jcbLookFeelDecorated =
		    new JCheckBox(RB.getString("DOptions.m_jcbLookFeelDecorated.text"), JFrame.isDefaultLookAndFeelDecorated());
		m_jcbLookFeelDecorated.setToolTipText(RB.getString("DOptions.m_jcbLookFeelDecorated.tooltip"));

		JPanel jpLookFeelDecoratedControls = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpLookFeelDecoratedControls.add(m_jcbLookFeelDecorated);

		JPanel jpDecorationNote = new JPanel(new FlowLayout(FlowLayout.LEFT));
		jpDecorationNote.add(new JLabel(RB.getString("DOptions.jlDecorationNote.text")));

		JPanel jpLookFeel = new JPanel(new BorderLayout());
		jpLookFeel.add(jpLookFeelControls, BorderLayout.NORTH);
		jpLookFeel.add(jpLookFeelDecoratedControls, BorderLayout.CENTER);
		jpLookFeel.add(jpDecorationNote, BorderLayout.SOUTH);
		
		// Setup a BouncyCastle Options tab
		JPanel jpBcOptions = new JPanel(new GridLayout(2, 1));
		m_jcbBcAllowUnsafeInteger = new JCheckBox(RB.getString("DOptions.jpBCoptions.allowunsafeinteger.text"), m_bBcAllowUnsafeInteger);
		m_jcbBcAllowUnsafeInteger.setToolTipText(RB.getString("DOptions.jpBCoptions.allowunsafeinteger.tooltip"));
		jpBcOptions.add(m_jcbBcAllowUnsafeInteger, BorderLayout.NORTH);

		

		// Add the panels to a tabbed pane
		JTabbedPane jtpOptions = new JTabbedPane();
		jtpOptions.addTab(RB.getString("DOptions.jpCaCerts.text"), null, jpCaCerts,
		    RB.getString("DOptions.jpCaCerts.tooltip"));
		jtpOptions.addTab(RB.getString("DOptions.jpLookFeel.text"), null, jpLookFeel,
		    RB.getString("DOptions.jpLookFeel.tooltip"));
		jtpOptions.addTab(RB.getString("DOptions.jpBCoptions.text"), null, jpBcOptions,
			RB.getString("DOptions.jpBCoptions.tooltip"));
		jtpOptions.setBorder(new EmptyBorder(5, 5, 5, 5));

		// OK and Cancel buttons

		JButton jbOK = getOkButton(false);
		JButton jbCancel = getCancelButton();

		JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		jpButtons.add(jbOK);
		jpButtons.add(jbCancel);

		// Put it all together
		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jtpOptions, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		setTitle(RB.getString("DOptions.Title"));

		getRootPane().setDefaultButton(jbOK);

		initDialog();
	}

	/**
	 * Store the user's option choices.
	 */
	private void storeOptions()
	{
		// Store CA certificates file
		m_fCaCertsFile = new File(m_jtfCaCertsFile.getText());

		// Store whether or not to use CA certificates keystore
		m_bUseCaCerts = m_jcbUseCaCerts.isSelected();

		// Store look & feel class name
		lookFeelClassName = lookFeelInfos.get(m_jcbLookFeel.getSelectedItem()).getClassName();

		// Store whether or not look & feel decoration should be used
		m_bLookFeelDecorated = m_jcbLookFeelDecorated.isSelected();
		
		m_bBcAllowUnsafeInteger =m_jcbBcAllowUnsafeInteger.isSelected();
	}

	/**
	 * Get the chosen CA certificates keystore file.
	 *
	 * @return The chosen CA certificates keystore file
	 */
	public File getCaCertsFile()
	{
		return m_fCaCertsFile;
	}

	/**
	 * Get whether or not the usage of CA certificates has been chosen.
	 *
	 * @return True if it has, false otherwise
	 */
	public boolean isUseCaCerts()
	{
		return m_bUseCaCerts;
	}

	/**
	 * Get the chosen look &amp; feel class name.
	 *
	 * @return The chosen look &amp; feel class name
	 */
	public String getLookFeelClassName()
	{
		return lookFeelClassName;
	}

	/**
	 * Get whether or not the look &amp; feel should be used for window decoration.
	 *
	 * @return True id it should, false otherwise.
	 */
	public boolean isLookFeelDecoration()
	{
		return m_bLookFeelDecorated;
	}

	/**
	 * Browse button pressed or otherwise activated. Allow the user to choose a CA certs file.
	 */
	private void browsePressed()
	{
		JFileChooser chooser = FileChooserFactory.getKeyStoreFileChooser(null);

		if (m_fCaCertsFile.getParentFile().exists())
		{
			chooser.setCurrentDirectory(m_fCaCertsFile.getParentFile());
		}

		chooser.setDialogTitle(RB.getString("DOptions.ChooseCACertsKeyStore.Title"));

		chooser.setMultiSelectionEnabled(false);

		int iRtnValue = chooser.showDialog(this, RB.getString("DOptions.CaCertsKeyStoreFileChooser.button"));
		if (iRtnValue == JFileChooser.APPROVE_OPTION)
		{
			m_jtfCaCertsFile.setText(chooser.getSelectedFile().toString());
			m_jtfCaCertsFile.setCaretPosition(0);
		}
	}

	/**
	 * Reset CA certificates file to default button pressed or otherwise activated.
	 */
	private void resetPressed()
	{
		m_fCaCertsFile = FPortecle.DEFAULT_CA_CERTS_FILE;
		m_jtfCaCertsFile.setText(m_fCaCertsFile.getAbsolutePath());
		m_jtfCaCertsFile.setCaretPosition(0);
	}

	@Override
	protected void okPressed()
	{
		storeOptions();
		super.okPressed();
	}

	/** 
	 * Preference: is option enabled to allow BC do relaxed integer parsing?
	 * @return True if option may be enabled, false otherwise.
	 */
	public boolean isBcAllowUnsafeInteger()
	{
		return m_bBcAllowUnsafeInteger;
	}

	public void setBcAllowUnsafeInteger(boolean m_bBcAllowUnsafeInteger)
	{
		this.m_bBcAllowUnsafeInteger =m_bBcAllowUnsafeInteger;
	}
}
