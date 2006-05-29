/*
 * DThrowable.java
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

package net.sf.portecle.gui.error;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

/**
 * Displays an throwable message with the option to display the stack trace.
 */
public class DThrowable
    extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/gui/error/resources");

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
    public DThrowable(JFrame parent, String sTitle, boolean bModal,
        Throwable throwable)
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
    public DThrowable(JDialog parent, String sTitle, boolean bModal,
        Throwable throwable)
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
        JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));

        JButton jbDetails = new JButton(
            m_res.getString("DThrowable.jbDetails.text"));
        jbDetails.setMnemonic(m_res.getString("DThrowable.jbDetails.mnemonic").charAt(
            0));

        jbDetails.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                showThrowableDetail();
            }
        });

        JButton jbOK = new JButton(m_res.getString("DThrowable.jbOK.text"));
        jbOK.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                okPressed();
            }
        });

        jpButtons.add(jbOK);
        jpButtons.add(jbDetails);

        JPanel jpThrowable = new JPanel(new FlowLayout(FlowLayout.CENTER));
        jpThrowable.setBorder(new EmptyBorder(5, 5, 5, 5));
        jpThrowable.add(new JLabel(m_throwable.toString()));

        getContentPane().add(jpThrowable, BorderLayout.CENTER);
        getContentPane().add(jpButtons, BorderLayout.SOUTH);

        setResizable(false);

        addWindowListener(new WindowAdapter()
        {
            public void windowClosing(WindowEvent evt)
            {
                closeDialog();
            }
        });

        getRootPane().setDefaultButton(jbOK);

        pack();
    }

    /**
     * Shows the Throwable Detail dialog.
     */
    private void showThrowableDetail()
    {
        DThrowableDetail dThrowableDetail = new DThrowableDetail(this, true,
            m_throwable);
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
