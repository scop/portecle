/*
 * DGetPassword.java
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

package net.sf.portecle.gui.password;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import java.util.*;

/**
 * Dialog used for entering a masked password.
 */
public class DGetPassword extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/gui/password/resources");

    /** Password entry label */
    private JLabel m_jlPassword;

    /** Password entry password field */
    private JPasswordField m_jpfPassword;

    /** Panel to hold password entry components */
    private JPanel m_jpPassword;

    /** OK button to confirm password entry */
    private JButton m_jbOK;

    /** Cancel to button to cancel password entry */
    private JButton m_jbCancel;

    /** Panel to hold OK and cancel buttons */
    private JPanel m_jpButtons;

    /** Stores password entered */
    private char[] m_cPassword;

    /** Key from input map to action map for the cancel button */
    private static final String CANCEL_KEY = "CANCEL_KEY";

    /**
     * Creates new DGetPassword dialog where the parent is a frame.
     *
     * @param parent Parent frame
     * @param sTitle The dialog's title
     * @param bModal Is dialog modal?
     */
    public DGetPassword(JFrame parent, String sTitle, boolean bModal)
    {
        super(parent, sTitle, bModal);
        initComponents();
    }
    /**
     * Creates new DGetPassword dialog where the parent is a dialog.
     *
     * @param parent Parent dialog
     * @param sTitle The dialog's title
     * @param bModal Is dialog modal?
     */
    public DGetPassword(JDialog parent, String sTitle, boolean bModal)
    {
        super(parent, sTitle, bModal);
        initComponents();
    }

    /**
     * Get the password set in the dialog.
     *
     * @return The password or null if none was set
     */
    public char[] getPassword()
    {
        return m_cPassword;
    }

    /**
     * Initialise the dialog's GUI components.
     */
    private void initComponents()
    {
        getContentPane().setLayout(new BorderLayout());

        m_jlPassword = new JLabel(
            m_res.getString("DGetPassword.m_jlPassword.text"));
        m_jpfPassword = new JPasswordField(15);

        m_jbOK = new JButton(m_res.getString("DGetPassword.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        m_jbCancel = new JButton(
            m_res.getString("DGetNewPassword.m_jbCancel.text"));
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

        m_jpPassword = new JPanel(new FlowLayout(FlowLayout.CENTER));
        m_jpPassword.add(m_jlPassword);
        m_jpPassword.add(m_jpfPassword);
        m_jpPassword.setBorder(new EmptyBorder(5, 5, 5, 5));

        m_jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
        m_jpButtons.add(m_jbOK);
        m_jpButtons.add(m_jbCancel);

        getContentPane().add(m_jpPassword, BorderLayout.CENTER);
        getContentPane().add(m_jpButtons, BorderLayout.SOUTH);

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        setResizable(false);

        getRootPane().setDefaultButton(m_jbOK);

        pack();
    }

    /**
     * OK button pressed or otherwise activated.
     */
    private void okPressed()
    {
        m_cPassword = m_jpfPassword.getPassword();
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
     * Close the dialog.
     */
    private void closeDialog()
    {
        setVisible(false);
        dispose();
    }
}
