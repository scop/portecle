/*
 * FHelp.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option)any later version.
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

package net.sf.portecle.gui.help;

import java.util.*;
import java.io.*;
import java.text.MessageFormat;
import java.awt.*;
import java.awt.event.*;
import java.net.URL;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

/**
 * Simple help system that displays two panes: a table of contents
 * and the current help topic.  Ruidimentary naigation is provided
 * using the home, forward and back buttons of the tool bar.
 */
public class FHelp extends JFrame implements HistoryEventListener
{
    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/gui/help/resources");

    /** Help frame's title */
    private String m_sTitle;

    /** Split pane to hold help contents and current topic */
    private JSplitPane m_jspHelp;

    /** Editor pane to hold contents */
    private JEditorPane m_jepContents;

    /** Scroll pane for contents */
    private JScrollPane m_jspContents;

    /** Editor pane to hold topic */
    private JEditorPane m_jepTopic;

    /** Scroll pane for topic */
    private JScrollPane m_jspTopic;

    /** Help toolbar */
    private JToolBar m_jtbTools;

    /** Home toolbar button */
    private JButton m_jbHome;

    /** Back toolbar button */
    private JButton m_jbBack;

    /** Forward toolbar button */
    private JButton m_jbForward;

    /** History home page */
    private URL m_home;

    /** Help navigation history */
    private History m_history;

    /**
     * Constructs a new help window with the specified title, icon, home page,
     * and contents page.
     *
     * @param sTitle A title for the window
     * @param home URL of the help home page
     * @param toc URL of the help contents page
     */
    public FHelp(String sTitle, URL home, URL toc)
    {
        super(sTitle);

        m_sTitle = sTitle;

        // Home button
        m_jbHome = new JButton();
        m_jbHome.setFocusable(false);
        m_jbHome.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FHelp.m_jbHome.image")))));
        m_jbHome.setToolTipText(m_res.getString("FHelp.m_jbHome.tooltip"));
        m_jbHome.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                try
                {
                    m_jepTopic.setPage(m_home);
                    m_history.visit(m_home);
                }
                catch (IOException ex)
                {
                    JOptionPane.showMessageDialog(FHelp.this,
                                                  MessageFormat.format(m_res.getString("FHelp.NoLocateUrl.message"), new Object[]{m_home}),
                                                  m_sTitle, JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // Back button
        m_jbBack = new JButton();
        m_jbBack.setFocusable(false);
        m_jbBack.setEnabled(false);
        m_jbBack.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FHelp.m_jbBack.image")))));
        m_jbBack.setToolTipText(m_res.getString("FHelp.m_jbBack.tooltip"));
        m_jbBack.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                URL temp = m_history.goBack();

                if (temp != null)
                {
                    try
                    {
                        m_jepTopic.setPage(temp);
                    }
                    catch (IOException ex)
                    {
                        JOptionPane.showMessageDialog(FHelp.this,
                                                      MessageFormat.format(m_res.getString("FHelp.NoLocateUrl.message"), new Object[]{temp}),
                                                      m_sTitle, JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        });

        // Forward button
        m_jbForward = new JButton();
        m_jbForward.setFocusable(false);
        m_jbForward.setEnabled(false);
        m_jbForward.setIcon(new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FHelp.m_jbForward.image")))));
        m_jbForward.setToolTipText(m_res.getString("FHelp.m_jbForward.tooltip"));
        m_jbForward.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                URL temp = m_history.goForward();
                if (temp != null)
                {
                    try
                    {
                        m_jepTopic.setPage(temp);
                    }
                    catch (IOException ex)
                    {
                        JOptionPane.showMessageDialog(FHelp.this,
                                                      MessageFormat.format(m_res.getString("FHelp.NoLocateUrl.message"), new Object[]{temp}),
                                                      m_sTitle, JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        });

        // Put buttons in toolbar
        m_jtbTools = new JToolBar(m_sTitle);
        m_jtbTools.setFloatable(false);
        m_jtbTools.setRollover(true);
        m_jtbTools.add(m_jbHome);
        m_jtbTools.add(m_jbBack);
        m_jtbTools.add(m_jbForward);

        // Table of contents pane
        m_jepContents = new JEditorPane();
        m_jepContents.setEditable(false);
        m_jepContents.setPreferredSize(new Dimension(300, 400));

        m_jepContents.addHyperlinkListener(new HyperlinkListener() {
            public void hyperlinkUpdate(HyperlinkEvent evt)
            {
                try
                {
                    if (evt.getEventType() == HyperlinkEvent.EventType.ACTIVATED)
                    {
                        m_jepTopic.setPage(evt.getURL());
                        m_history.visit(evt.getURL());
                    }
                }
                catch (IOException ex)
                {
                    JOptionPane.showMessageDialog(FHelp.this,
                                                  MessageFormat.format(m_res.getString("FHelp.NoLocateUrl.message"), new Object[]{evt.getURL()}),
                                                  m_sTitle, JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        try
        {
            m_jepContents.setPage(toc);
        }
        catch (IOException ex)
        {
            JOptionPane.showMessageDialog(FHelp.this,
                                          MessageFormat.format(m_res.getString("FHelp.NoLocateUrl.message"), new Object[]{toc}),
                                          m_sTitle, JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Help topic pane
        m_jepTopic = new JEditorPane();
        m_jepTopic.setEditable(false);
        m_jepTopic.setPreferredSize(new Dimension(450, 400));

        m_jepTopic.addHyperlinkListener(new HyperlinkListener()
        {
            public void hyperlinkUpdate(HyperlinkEvent evt)
            {
                try
                {
                    if (evt.getEventType() == HyperlinkEvent.EventType.ACTIVATED)
                    {
                        m_jepTopic.setPage(evt.getURL());
                        m_history.visit(evt.getURL());
                    }
                }
                catch (IOException ex)
                {
                    JOptionPane.showMessageDialog(FHelp.this,
                                                  MessageFormat.format(m_res.getString("FHelp.NoLocateUrl.message"), new Object[]{evt.getURL()}),
                                                  m_sTitle, JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        try
        {
            m_home = home;
            m_jepTopic.setPage(m_home);
        }
        catch (IOException ex)
        {
            JOptionPane.showMessageDialog(FHelp.this,
                                          MessageFormat.format(m_res.getString("FHelp.NoLocateUrl.message"), new Object[]{m_home}),
                                          m_sTitle, JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Initialise navigation history
        m_history = new History(home);
        m_history.addHistoryEventListener(this);

        // Make panes scrollable
        m_jspTopic = new JScrollPane(m_jepTopic);
        m_jspContents = new JScrollPane(m_jepContents);

        // Put panes into a horizontal split pane
        m_jspHelp = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, m_jspContents, m_jspTopic);
        m_jspHelp.setResizeWeight(0.0);
        m_jspHelp.resetToPreferredSizes();
        m_jspHelp.setBorder(new CompoundBorder(new EtchedBorder(),
                            new EmptyBorder(3, 3, 3, 3)));

        // Put it all together
        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(m_jtbTools, BorderLayout.NORTH);
        getContentPane().add(m_jspHelp, BorderLayout.CENTER);

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt)
            {
                setVisible(false);
            }
        });

        setIconImage(Toolkit.getDefaultToolkit().createImage(getClass().getResource(m_res.getString("FHelp.Icon.image"))));

        pack();
    }

    /**
     * Show the help window?
     *
     * @param bShow If true show the help window otherwise hide it
     */
    public void setVisible(boolean bShow)
    {
        if (bShow)
        {
            // If the frame was minimised during its last display it won't be after this
            setState(Frame.NORMAL);
        }

        super.setVisible(bShow);
    }

    /**
     * Notifies the help that the history status has changed and it should adjust its buttons accordingly.
     *
     * @param evt The HistoryEvent
     */
    public void historyStatusChanged(HistoryEvent evt)
    {
        m_jbBack.setEnabled(evt.isBackAvailable());
        m_jbForward.setEnabled(evt.isForwardAvailable());
    }
}
