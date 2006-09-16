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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package net.sf.portecle.gui.password;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.KeyStroke;
import javax.swing.border.EmptyBorder;

/**
 * Dialog used for entering a masked password.
 */
public class DGetPassword
    extends JDialog
{
    /** Key from input map to action map for the cancel button */
    private static final String CANCEL_KEY = "CANCEL_KEY";

    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/gui/password/resources");

    /** Password entry password field */
    private JPasswordField m_jpfPassword;

    /** Stores password entered */
    private char[] m_cPassword;

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
        if (m_cPassword == null) {
            return null;
        }
        char[] copy = new char[m_cPassword.length];
        System.arraycopy(m_cPassword, 0, copy, 0, copy.length);
        return copy;
    }

    /**
     * Initialise the dialog's GUI components.
     */
    private void initComponents()
    {
        getContentPane().setLayout(new BorderLayout());

        JLabel jlPassword = new JLabel(
            m_res.getString("DGetPassword.jlPassword.text"));
        m_jpfPassword = new JPasswordField(15);

        JButton jbOK = new JButton(m_res.getString("DGetPassword.jbOK.text"));
        jbOK.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                okPressed();
            }
        });

        JButton jbCancel = new JButton(
            m_res.getString("DGetNewPassword.jbCancel.text"));
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

        JPanel jpPassword = new JPanel(new FlowLayout(FlowLayout.CENTER));
        jpPassword.add(jlPassword);
        jpPassword.add(m_jpfPassword);
        jpPassword.setBorder(new EmptyBorder(5, 5, 5, 5));

        JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
        jpButtons.add(jbOK);
        jpButtons.add(jbCancel);

        getContentPane().add(jpPassword, BorderLayout.CENTER);
        getContentPane().add(jpButtons, BorderLayout.SOUTH);

        addWindowListener(new WindowAdapter()
        {
            public void windowClosing(WindowEvent evt)
            {
                closeDialog();
            }
        });

        setResizable(false);

        getRootPane().setDefaultButton(jbOK);

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
