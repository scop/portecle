/*
 * DGetAlias.java
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

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import java.util.ResourceBundle;

/**
 * Dialog used for entering a KeyStore alias.
 */
class DGetAlias extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Panel to hold the alias entry controls */
    private JPanel m_jpAlias;

    /** Alias label */
    private JLabel m_jlAlias;

    /** Alias text field */
    private JTextField m_jtfAlias;

    /** Panel to hold confirmation buttons */
    private JPanel m_jpButtons;

    /** OK button to confirm dialog */
    private JButton m_jbOK;

    /** Cancel button to cancel dialog */
    private JButton m_jbCancel;

    /** Stores the alias entered by the user */
    private String m_sAlias;

    /** Key from input map to action map for the cancel button */
    private static final String CANCEL_KEY = "CANCEL_KEY";

    /**
     * Creates new DGetAlias dialog where the parent is a frame.
     *
     * @param parent The parent frame
     * @param sTitle The dialog's title
     * @param bModal Is the dialog modal?
     * @param sOldAlias The alias to display initially
     */
    public DGetAlias(JFrame parent, String sTitle, boolean bModal, String sOldAlias)
    {
        super(parent, sTitle, bModal);
        initComponents(sOldAlias);
    }

    /**
     * Creates new DGetAlias dialog where the parent is a dialog.
     *
     * @param parent The parent dialog
     * @param sTitle The dialog's title
     * @param bModal Is the dialog modal?
     * @param sOldAlias The alias to display initially
     */
    public DGetAlias(JDialog parent, String sTitle, boolean bModal, String sOldAlias)
    {
        super(parent, sTitle, bModal);
        initComponents(sOldAlias);
    }

    /**
     * Get the alias eneterd by the user.
     *
     * @return The alias, or null if none was entered
     */
    public String getAlias()
    {
        return m_sAlias;
    }

    /**
     * Initialise the dialog's GUI components.
     *
     * @param sOldAlias The alias to display initially
     */
    private void initComponents(String sOldAlias)
    {
        getContentPane().setLayout(new BorderLayout());

        m_jlAlias = new JLabel(m_res.getString("DGetAlias.m_jlAlias.text"));
        m_jtfAlias = new JTextField(15);

        if (sOldAlias != null)
        {
            m_jtfAlias.setText(sOldAlias);
            m_jtfAlias.setCaretPosition(0);
        }

        m_jbOK = new JButton(m_res.getString("DGetAlias.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        m_jbCancel = new JButton(m_res.getString("DGetAlias.m_jbCancel.text"));
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

        m_jpAlias = new JPanel(new FlowLayout(FlowLayout.CENTER));
        m_jpAlias.add(m_jlAlias);
        m_jpAlias.add(m_jtfAlias);
        m_jpAlias.setBorder(new EmptyBorder(5, 5, 5, 5));

        m_jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
        m_jpButtons.add(m_jbOK);
        m_jpButtons.add(m_jbCancel);

        getContentPane().add(m_jpAlias, BorderLayout.CENTER);
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
     * Check that the alias is valid, ie that it is not blank.
     *
     * @return True if the alias is valid, false otherwise
     */
    private boolean checkAlias()
    {
        String sAlias = new String(m_jtfAlias.getText().trim().toLowerCase());

        if (sAlias.length() > 0)
        {
            m_sAlias = m_jtfAlias.getText().trim();
            return true;
        }
        else
        {
            JOptionPane.showMessageDialog(this, m_res.getString("DGetAlias.AliasReq.message"),
                                          getTitle(), JOptionPane.WARNING_MESSAGE);
        }
        return false;
    }

    /**
     * OK button pressed or otherwise activated.
     */
    private void okPressed()
    {
        if (checkAlias())
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

    /** Closes the dialog */
    private void closeDialog()
    {
        setVisible(false);
        dispose();
    }
}
