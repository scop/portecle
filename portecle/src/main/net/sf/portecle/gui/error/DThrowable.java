/*
 * DThrowable.java
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

package net.sf.portecle.gui.error;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;

/**
 * Displays an throwable message with the option to display the stack trace.
 */
public class DThrowable extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/gui/error/resources");

    /** Panel to hold OK and Details buttons */
    private JPanel m_jpButtons;

    /** Details button to display the stack trace of the throwable */
    private JButton m_jbDetails;

    /** OK button to dismiss dialog */
    private JButton m_jbOK;

    /** Panel to hold throwable message */
    private JPanel m_jpThrowable;

    /** Label to display throwable message */
    private JLabel m_jlThrowable;

    /** Stores throwable to display */
    private Throwable m_throwable;

    /**
     * Creates new DThrowable dialog where the parent is a frame.
     *
     * @param bModal Create the dialog as modal?
     * @param parent Parent frame
     * @param throwable Throwable to display
     */
    public DThrowable(JFrame parent, boolean bModal, Throwable throwable)
    {
        super(parent, m_res.getString("DThrowable.Title"), bModal);
        m_throwable = throwable;
        initComponents();
    }

    /**
     * Creates new DThrowable dialog where the parent is a dialog.
     *
     * @param parent Parent dialog
     * @param bModal Create the dialog as modal?
     * @param throwable Throwable to display
     */
    public DThrowable(JDialog parent, boolean bModal, Throwable throwable)
    {
        super(parent, m_res.getString("DThrowable.Title"), bModal);
        m_throwable = throwable;
        initComponents();
    }

    /**
     * Creates new DThrowable dialog where the parent is a frame.
     *
     * @param bModal Create the dialog as modal?
     * @param sTitle Dialog title
     * @param parent Parent frame
     * @param throwable Throwable to display
     */
    public DThrowable(JFrame parent, String sTitle, boolean bModal, Throwable throwable)
    {
        super(parent, bModal);
        setTitle(sTitle);
        m_throwable = throwable;
        initComponents();
    }

    /**
     * Creates new DThrowable dialog where the parent is a dialog.
     *
     * @param parent Parent dialog
     * @param sTitle Dialog title
     * @param bModal Create the dialog as modal?
     * @param throwable Throwable to display
     */
    public DThrowable(JDialog parent, String sTitle, boolean bModal, Throwable throwable)
    {
        super(parent, bModal);
        setTitle(sTitle);
        m_throwable = throwable;
        initComponents();
    }

    /**
     * Initialise the dialog's GUI components.
     */
    private void initComponents()
    {
        m_jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));

        m_jbDetails = new JButton(m_res.getString("DThrowable.m_jbDetails.text"));
        m_jbDetails.setMnemonic(m_res.getString("DThrowable.m_jbDetails.mnemonic").charAt(0));

        m_jbDetails.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                showThrowableDetail();
            }
        });

        m_jbOK = new JButton(m_res.getString("DThrowable.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        m_jpButtons.add(m_jbOK);
        m_jpButtons.add(m_jbDetails);

        m_jpThrowable = new JPanel(new FlowLayout(FlowLayout.CENTER));
        m_jpThrowable.setBorder(new EmptyBorder(5, 5, 5, 5));
        m_jlThrowable = new JLabel(m_throwable.toString());
        m_jpThrowable.add(m_jlThrowable);

        getContentPane().add(m_jpThrowable, BorderLayout.CENTER);
        getContentPane().add(m_jpButtons, BorderLayout.SOUTH);

        setResizable(false);

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        getRootPane().setDefaultButton(m_jbOK);

        pack();
    }

    /**
     * Shows the Throwable Detail dialog.
     */
    private void showThrowableDetail()
    {
        DThrowableDetail dThrowableDetail = new DThrowableDetail(this, true, m_throwable);
        dThrowableDetail.setLocationRelativeTo(this);
        dThrowableDetail.setVisible(true);
    }

    /**
     * OK button pressed or otherwise activated.
     */
    private void okPressed()
    {
        closeDialog();
    }

    /**
     * Hides the Throwable dialog.
     */
    private void closeDialog()
    {
        setVisible(false);
        dispose();
    }
}
