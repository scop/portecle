/*
 * DGetNewPassword.java
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
 * Dialog used for entering and confirming a password.
 */
public class DGetNewPassword extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/gui/password/resources");

    /** Panel to hold password entry components */
    private JPanel m_jpPassword;

    /** Label for first password */
    private JLabel m_jlFirst;

    /** First password entry password field */
    private JPasswordField m_jpfFirst;

    /** Label for confirmation password */
    private JLabel m_jlConfirm;

    /** Password confirmation entry password field */
    private JPasswordField m_jpfConfirm;

    /** Panel to hold OK and cancel buttons */
    private JPanel m_jpButtons;

    /** OK button to confirm password entry */
    private JButton m_jbOK;

    /** Cancel to button to cancel password entry */
    private JButton m_jbCancel;

    /** Stores new password entered */
    private char[] m_cPassword;

    /** Key from input map to action map for the cancel button */
    private static final String CANCEL_KEY = "CANCEL_KEY";

    /**
     * Creates new DGetNewPassword dialog where the parent is a frame.
     *
     * @param parent Parent frame
     * @param bModal Is dialog modal?
     */
    public DGetNewPassword(JFrame parent, boolean bModal)
    {
        super(parent, m_res.getString("DGetNewPassword.Title"), bModal);
    }

    /**
     * Creates new DGetNewPassword dialog where the parent is a frame.
     *
     * @param parent Parent frame
     * @param sTitle The dialog's title
     * @param bModal Is dialog modal?
     */
    public DGetNewPassword(JFrame parent, String sTitle, boolean bModal)
    {
        super(parent, sTitle, bModal);
        initComponents();
    }

    /**
     * Creates new DGetNewPassword dialog where the parent is a dialog.
     *
     * @param parent Parent dialog
     * @param bModal Is dialog modal?
     */
    public DGetNewPassword(JDialog parent, boolean bModal)
    {
        this(parent, m_res.getString("DGetNewPassword.Title"), bModal);
    }

    /**
     * Creates new DGetNewPassword dialog where the parent is a dialog.
     *
     * @param parent Parent dialog
     * @param sTitle The dialog's title
     * @param bModal Is dialog modal?
     */
    public DGetNewPassword(JDialog parent, String sTitle, boolean bModal)
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

        m_jlFirst = new JLabel(
            m_res.getString("DGetNewPassword.m_jlFirst.text"));
        m_jlConfirm = new JLabel(
            m_res.getString("DGetNewPassword.m_jlConfirm.text"));
        m_jpfFirst = new JPasswordField(15);
        m_jpfConfirm = new JPasswordField(15);

        m_jbOK = new JButton(m_res.getString("DGetNewPassword.m_jbOK.text"));
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

        m_jpPassword = new JPanel(new GridLayout(2, 2, 5, 5));
        m_jpPassword.add(m_jlFirst);
        m_jpPassword.add(m_jpfFirst);
        m_jpPassword.add(m_jlConfirm);
        m_jpPassword.add(m_jpfConfirm);
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
     * Check for the following:
     * <ul>
     *     <li>That the user has supplied and confirmed a password.
     *     <li>That the password's match.
     *     <li>That they have a length greater than a perscribed minimum.
     * </ul>
     * Store the new password in this object.
     *
     * @return True, if the user's dialog entry matches the above criteria,
     *         false otherwise
     */
    private boolean checkPassword()
    {
        String sFirstPassword = new String(m_jpfFirst.getPassword());
        String sConfirmPassword = new String(m_jpfConfirm.getPassword());

        if (sFirstPassword.equals(sConfirmPassword))
        {
            m_cPassword = sFirstPassword.toCharArray();
            return true;
        }
        else
        {
            JOptionPane.showMessageDialog(
                this, m_res.getString("PasswordsNoMatch.message"),
                getTitle(), JOptionPane.WARNING_MESSAGE);
        }

        return false;
    }

    /**
     * OK button pressed or otherwise activated.
     */
    private void okPressed()
    {
        if (checkPassword())
        {
            closeDialog();
        }
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
