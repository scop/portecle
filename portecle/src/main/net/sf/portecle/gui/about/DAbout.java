/*
 * DAbout.java
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

package net.sf.portecle.gui.about;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;

/**
 * An About dialog which displays an image of about information and a button
 * to access system information.
 */
public class DAbout extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/gui/about/resources");

    /** Label that contains the supplied about image */
    private JLabel m_jlAbout;

    /** OK button used to dismiss dialog */
    private JButton m_jbOK;

    /** Info button used to display system information */
    private JButton m_jbSystemInformation;

    /** Panel containing buttons */
    private JPanel m_jpButtons;

    /**
     * Creates new DAbout dialog where the parent is a frame.
     *
     * @param parent Parent frame
     * @param bModal Is dialog modal?
     * @param aboutImg The image containing the about information
     */
    public DAbout(JFrame parent, boolean bModal, Image aboutImg)
    {
        this(parent, m_res.getString("DAbout.Title"), bModal, aboutImg);
    }

    /**
     * Creates new DAbout dialog where the parent is a frame.
     *
     * @param parent Parent frame
     * @param sTitle The title of the dialog
     * @param bModal Is dialog modal?
     * @param aboutImg The image containing the about information
     */
    public DAbout(JFrame parent, String sTitle, boolean bModal, Image aboutImg)
    {
        super(parent, sTitle, bModal);
        initComponents(aboutImg);
    }

    /**
     * Initialise the dialog's GUI components.
     *
     * @param aboutImg The image that containing the about information
     */
    private void initComponents(Image aboutImg)
    {
        getContentPane().setLayout(new BorderLayout(0, 0));
        m_jlAbout = new JLabel(new ImageIcon(aboutImg));

        m_jbOK = new JButton(m_res.getString("DAbout.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        m_jbSystemInformation = new JButton(m_res.getString("DAbout.m_jbSystemInformation.text"));
        m_jbSystemInformation.setMnemonic(m_res.getString("DAbout.m_jbSystemInformation.mnemonic").charAt(0));

        m_jbSystemInformation.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                showSystemInformation();
            }
        });

        m_jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));
        m_jpButtons.setBorder(new EmptyBorder(5, 0, 5, 0));
        m_jpButtons.add(m_jbOK);
        m_jpButtons.add(m_jbSystemInformation);

        getContentPane().add(m_jlAbout, BorderLayout.CENTER);
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
     * Shows the System Information dialog.
     */
    private void showSystemInformation()
    {
        DSystemInformation dSystemInformation = new DSystemInformation(this, true);
        dSystemInformation.setLocationRelativeTo(this);
        dSystemInformation.setVisible(true);
    }

    /**
     * OK button pressed or otherwise activated.
     */
    private void okPressed()
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
