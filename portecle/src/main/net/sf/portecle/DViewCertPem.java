/*
 * DViewCertPem.java
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
import java.security.cert.*;
import java.util.ResourceBundle;

import javax.swing.*;
import javax.swing.border.*;

import net.sf.portecle.crypto.CryptoException;
import net.sf.portecle.crypto.X509CertUtil;

/**
 * Displays an X.509 certificate's PEM encoding.
 */
class DViewCertPem extends JDialog
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/resources");

    /** Panel to hold OK button */
    private JPanel m_jpOK;

    /** OK button to dismiss dialog */
    private JButton m_jbOK;

    /** Panel to hold scroll pane in */
    private JPanel m_jpCertPem;

    /** Scroll pane to hold text area in */
    private JScrollPane m_jspCertPem;

    /** Text area to display certificate's PEM encoding in */
    private JTextArea m_jtaCertPem;

    /** Stores certificate to display */
    private X509Certificate m_cert;

    /**
     * Creates new DViewCertPem dialog where the parent is a frame.
     *
     * @param parent Parent frame
     * @param sTitle The dialog title
     * @param bModal Is dialog modal?
     * @param cert Certificate to display encoding for
     * @throws CryptoException A problem was encountered getting the
     * certificate's PEM encoding
     */
    public DViewCertPem(JFrame parent, String sTitle, boolean bModal,
                        X509Certificate cert)
        throws CryptoException
    {
        super(parent, sTitle, bModal);
        m_cert = cert;
        initComponents();
    }

    /**
     * Creates new DViewCertPem dialog where the parent is a dialog.
     *
     * @param parent Parent dialog
     * @param sTitle The dialog title
     * @param bModal Is dialog modal?
     * @param cert Certificate to display encoding for
     * @throws CryptoException A problem was encountered getting the
     * certificate's PEM encoding
     */
    public DViewCertPem(JDialog parent, String sTitle, boolean bModal,
                        X509Certificate cert)
        throws CryptoException
    {
        super(parent, sTitle, bModal);
        m_cert = cert;
        initComponents();
    }

    /**
     * Initialise the dialog's GUI components.
     *
     * @throws CryptoException A problem was encountered getting the
     * certificate's PEM encoding
     */
    private void initComponents() throws CryptoException
    {
        m_jpOK = new JPanel(new FlowLayout(FlowLayout.CENTER));

        m_jbOK = new JButton(m_res.getString("DViewCertPem.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        m_jpOK.add(m_jbOK);

        m_jpCertPem = new JPanel(new BorderLayout());
        m_jpCertPem.setBorder(new EmptyBorder(5, 5, 5, 5));

        // Load text area with the PEM encoding
        m_jtaCertPem = new JTextArea(X509CertUtil.getCertEncodedPem(m_cert));
        m_jtaCertPem.setCaretPosition(0);
        m_jtaCertPem.setEditable(false);
        m_jtaCertPem.setFont(
            new Font("Monospaced", Font.PLAIN,
                     m_jtaCertPem.getFont().getSize()));

        m_jspCertPem = new JScrollPane(
            m_jtaCertPem,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
            JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        m_jspCertPem.setPreferredSize(new Dimension(500, 300));
        m_jpCertPem.add(m_jspCertPem, BorderLayout.CENTER);

        getContentPane().add(m_jpCertPem, BorderLayout.CENTER);
        getContentPane().add(m_jpOK, BorderLayout.SOUTH);

        setResizable(true);

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        getRootPane().setDefaultButton(m_jbOK);

        pack();

        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                m_jbOK.requestFocus();
            }
        });
    }

    /**
     * OK button pressed or otherwise activated.
     */
    private void okPressed()
    {
        closeDialog();
    }

    /**
     * Hides the dialog.
     */
    private void closeDialog()
    {
        setVisible(false);
        dispose();
    }
}
