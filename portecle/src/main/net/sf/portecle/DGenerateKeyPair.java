/*
 * DGenerateKeyPair.java
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

package net.sf.portecle;

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;

import net.sf.portecle.crypto.*;

/**
 * Dialog used to choose the parameters required for key pair generation.
 * The user may select an asymmetric key generation algorithm of DSA or RSA and
 * enter a key size in bits.
 */
class DGenerateKeyPair extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Panel for key algorithm controls */
    private JPanel m_jpKeyAlg;

    /** Key algorithm label */
    private JLabel m_jlKeyAlg;

    /** Radio button for a DSA key algorithm */
    private JRadioButton m_jrbDSA;

    /** Radio button for an RSA key algorithm */
    private JRadioButton m_jrbRSA;

    /** Panel for key size controls */
    private JPanel m_jpKeySize;

    /** Key size label */
    private JLabel m_jlKeySize;

    /** Key size text field */
    private JTextField m_jtfKeySize;

    /** Panel for all option controls */
    private JPanel m_jpOptions;

    /** Panel for confirmation button controls */
    private JPanel m_jpButtons;

    /** OK button to confirm dialog */
    private JButton m_jbOK;

    /** Cancel button to cancel dialog */
    private JButton m_jbCancel;

    /** Key from input map to action map for the cancel button */
    private static final String CANCEL_KEY = "CANCEL_KEY";

    /** Indicator for an invalid keysize */
    private static final int BAD_KEYSIZE = -1;

    /** Default keysize for the dialog */
    private static final String DEFAULT_KEYSIZE =
        m_res.getString("DGenerateKeyPair.DefaultKeySize");

    /** Key pair type chosen for generation */
    private KeyPairType m_keyPairType;

    /** Key size chosen */
    private int m_iKeySize;

     /** Records whether or not correct parameters are entered */
    private boolean m_bSuccess;

    /**
     * Creates new DGenerateKeyPair dialog where the parent is a frame.
     *
     * @param parent The parent frame
     * @param bModal Is dialog modal?
     */
    public DGenerateKeyPair(JFrame parent, boolean bModal)
    {
        super(parent, bModal);
        initComponents();
    }

    /**
     * Creates new DGenerateKeyPair dialog where the parent is a dialog.
     *
     * @param parent The parent dialog
     * @param bModal Is dialog modal?
     */
    public DGenerateKeyPair(JDialog parent, boolean bModal)
    {
        super(parent, bModal);
        initComponents();
    }

    /**
     * Initialise the dialog's GUI components.
     */
    private void initComponents()
    {
        m_jlKeyAlg = new JLabel(
            m_res.getString("DGenerateKeyPair.m_jlKeyAlg.text"));
        m_jrbDSA = new JRadioButton(
            m_res.getString("DGenerateKeyPair.m_jrbDSA.text"), true);
        m_jrbDSA.setToolTipText(
            m_res.getString("DGenerateKeyPair.m_jrbDSA.tooltip"));
        m_jrbRSA = new JRadioButton(
            m_res.getString("DGenerateKeyPair.m_jrbRSA.text"), false);
        m_jrbRSA.setToolTipText(
            m_res.getString("DGenerateKeyPair.m_jrbRSA.tooltip"));
        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(m_jrbDSA);
        buttonGroup.add(m_jrbRSA);
        m_jpKeyAlg = new JPanel(new FlowLayout(FlowLayout.LEFT));
        m_jpKeyAlg.add(m_jlKeyAlg);
        m_jpKeyAlg.add(m_jrbDSA);
        m_jpKeyAlg.add(m_jrbRSA);

        m_jlKeySize = new JLabel(
            m_res.getString("DGenerateKeyPair.m_jlKeySize.text"));
        m_jtfKeySize = new JTextField(5);
        m_jtfKeySize.setText(DEFAULT_KEYSIZE);
        m_jtfKeySize.setToolTipText(
            m_res.getString("DGenerateKeyPair.m_jtfKeySize.tooltip"));
        m_jpKeySize = new JPanel(new FlowLayout(FlowLayout.LEFT));
        m_jpKeySize.add(m_jlKeySize);
        m_jpKeySize.add(m_jtfKeySize);

        m_jpOptions = new JPanel(new GridLayout(2, 1, 5, 5));
        m_jpOptions.add(m_jpKeyAlg);
        m_jpOptions.add(m_jpKeySize);

        m_jpOptions.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5),
                                                 new EtchedBorder()));

        m_jbOK = new JButton(m_res.getString("DGenerateKeyPair.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        m_jbCancel = new JButton(
            m_res.getString("DGenerateKeyPair.m_jbCancel.text"));
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

        m_jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
        m_jpButtons.add(m_jbOK);
        m_jpButtons.add(m_jbCancel);

        getContentPane().add(m_jpOptions, BorderLayout.CENTER);
        getContentPane().add(m_jpButtons, BorderLayout.SOUTH);

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        setTitle(m_res.getString("DGenerateKeyPair.Title"));
        setResizable(false);

        getRootPane().setDefaultButton(m_jbOK);

        pack();
    }

    /**
     * Validate the chosen key pair generation parameters.
     *
     * @return True if the key pair generation paremeters are valid,
     * false otherwise
     */
    private boolean validateKeyGenParameters()
    {
        // Check key size
        int iKeySize = validateKeySize();
        if (iKeySize == BAD_KEYSIZE)
        {
            return false; // Invalid
        }
        m_iKeySize = iKeySize;

        // Get key pair generation algorithm
        m_keyPairType =
            m_jrbDSA.isSelected() ? KeyPairType.DSA : KeyPairType.RSA;

        m_bSuccess = true;

        // Key pair generation parameters verified
        return true;
    }

    /**
     * Validate the key size value the user has entered as a string
     * and convert it to an integer.  Validate the key size is
     * supported for the particular key pair generation algorithm they
     * have chosen.
     *
     * @return The Validity value or BAD_KEYSIZE if it is not valid
     */
    private int validateKeySize()
    {
        String sKeySize = m_jtfKeySize.getText().trim();
        int iKeySize;

        if (sKeySize.length() == 0)
        {
            JOptionPane.showMessageDialog(
                this,
                m_res.getString("DGenerateKeyPair.KeySizeReq.message"),
                getTitle(),
                JOptionPane.WARNING_MESSAGE);
            return BAD_KEYSIZE;
        }

        try
        {
            iKeySize = Integer.parseInt(sKeySize);
        }
        catch (NumberFormatException ex)
        {
            JOptionPane.showMessageDialog(
                this,
                m_res.getString("DGenerateKeyPair.KeySizeIntegerReq.message"),
                getTitle(),
                JOptionPane.WARNING_MESSAGE);
            return BAD_KEYSIZE;
        }

        if (m_jrbDSA.isSelected())
        {
            if (iKeySize < 512 || iKeySize > 1024 || (iKeySize % 64) != 0)
            {
                JOptionPane.showMessageDialog(
                    this,
                    m_res.getString(
                        "DGenerateKeyPair.UnsupportedDsaKeySize.message"),
                    getTitle(),
                    JOptionPane.WARNING_MESSAGE);
                return BAD_KEYSIZE;
            }
        }
        else
        {
            if (iKeySize < 512 || iKeySize > 2048)
            {
                JOptionPane.showMessageDialog(
                    this,
                    m_res.getString(
                        "DGenerateKeyPair.UnsupportedRsaKeySize.message"),
                    getTitle(),
                    JOptionPane.WARNING_MESSAGE);
                return BAD_KEYSIZE;
            }
        }

        return iKeySize;
    }

    /**
     * OK button pressed or otherwise activated.
     */
    private void okPressed()
    {
        if (validateKeyGenParameters())
        {
            closeDialog();
        }
    }

    /**
     * Get the key pair size chosen.
     *
     * @return The key pair size
     */
    public int getKeySize()
    {
        return m_iKeySize;
    }

    /**
     * Get the key pair type chosen.
     *
     * @return The key pair generation type
     */
    public KeyPairType getKeyPairType()
    {
        return m_keyPairType;
    }

    /**
     * Have the parameters been entered correctly?
     *
     * @return True if they have, false otherwise
     */
    public boolean isSuccessful()
    {
        return m_bSuccess;
    }

    /**
     * Cancel button pressed or otherwise activated.
     */
    private void cancelPressed()
    {
        closeDialog();
    }

    /** Closes the dialog */
    private void closeDialog()
    {
        setVisible(false);
        dispose();
    }
}
