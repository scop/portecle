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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package net.sf.portecle.gui.help;

import static net.sf.portecle.FPortecle.RB;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.net.URL;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JEditorPane;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JToolBar;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;

/**
 * Simple help system that displays two panes: a table of contents and the current help topic. Rudimentary navigation is
 * provided using the home, forward and back buttons of the tool bar.
 */
public class FHelp
    extends JFrame
    implements HistoryEventListener
{
	/** Help frame's title */
	private final String m_sTitle;

	/** History home page */
	private URL m_home;

	/** Back toolbar button */
	private final JButton m_jbBack;

	/** Forward toolbar button */
	private final JButton m_jbForward;

	/** Help navigation history */
	private final History m_history;

	/**
	 * Constructs a new help window with the specified title, icon, home page, and contents page.
	 * 
	 * @param sTitle A title for the window
	 * @param home URL of the help home page
	 * @param toc URL of the help contents page
	 */
	public FHelp(String sTitle, URL home, URL toc)
	{
		super(sTitle);

		m_sTitle = sTitle;

		// Help topic pane
		final JEditorPane jepTopic = new JEditorPane();
		jepTopic.setEditable(false);
		jepTopic.setPreferredSize(new Dimension(450, 400));

		jepTopic.addHyperlinkListener(new HyperlinkListener()
		{
			@Override
			public void hyperlinkUpdate(HyperlinkEvent evt)
			{
				try
				{
					if (evt.getEventType() == HyperlinkEvent.EventType.ACTIVATED)
					{
						jepTopic.setPage(evt.getURL());
						m_history.visit(evt.getURL());
					}
				}
				catch (IOException ex)
				{
					JOptionPane.showMessageDialog(FHelp.this,
		                MessageFormat.format(RB.getString("FHelp.NoLocateUrl.message"), evt.getURL()), m_sTitle,
		                JOptionPane.ERROR_MESSAGE);
				}
			}
		});

		// Home button
		JButton jbHome = new JButton();
		jbHome.setFocusable(false);
		jbHome.setIcon(new ImageIcon(
		    Toolkit.getDefaultToolkit().createImage(getClass().getResource(RB.getString("FHelp.jbHome.image")))));
		jbHome.setToolTipText(RB.getString("FHelp.jbHome.tooltip"));
		jbHome.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent evt)
			{
				try
				{
					jepTopic.setPage(m_home);
					m_history.visit(m_home);
				}
				catch (IOException ex)
				{
					JOptionPane.showMessageDialog(FHelp.this,
		                MessageFormat.format(RB.getString("FHelp.NoLocateUrl.message"), m_home), m_sTitle,
		                JOptionPane.ERROR_MESSAGE);
				}
			}
		});

		// Back button
		m_jbBack = new JButton();
		m_jbBack.setFocusable(false);
		m_jbBack.setEnabled(false);
		m_jbBack.setIcon(new ImageIcon(
		    Toolkit.getDefaultToolkit().createImage(getClass().getResource(RB.getString("FHelp.m_jbBack.image")))));
		m_jbBack.setToolTipText(RB.getString("FHelp.m_jbBack.tooltip"));
		m_jbBack.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent evt)
			{
				URL temp = m_history.goBack();

				if (temp != null)
				{
					try
					{
						jepTopic.setPage(temp);
					}
					catch (IOException ex)
					{
						JOptionPane.showMessageDialog(FHelp.this,
		                    MessageFormat.format(RB.getString("FHelp.NoLocateUrl.message"), temp), m_sTitle,
		                    JOptionPane.ERROR_MESSAGE);
					}
				}
			}
		});

		// Forward button
		m_jbForward = new JButton();
		m_jbForward.setFocusable(false);
		m_jbForward.setEnabled(false);
		m_jbForward.setIcon(new ImageIcon(
		    Toolkit.getDefaultToolkit().createImage(getClass().getResource(RB.getString("FHelp.m_jbForward.image")))));
		m_jbForward.setToolTipText(RB.getString("FHelp.m_jbForward.tooltip"));
		m_jbForward.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent evt)
			{
				URL temp = m_history.goForward();
				if (temp != null)
				{
					try
					{
						jepTopic.setPage(temp);
					}
					catch (IOException ex)
					{
						JOptionPane.showMessageDialog(FHelp.this,
		                    MessageFormat.format(RB.getString("FHelp.NoLocateUrl.message"), temp), m_sTitle,
		                    JOptionPane.ERROR_MESSAGE);
					}
				}
			}
		});

		// Initialize navigation history
		m_history = new History(home);
		m_history.addHistoryEventListener(this);

		// Put buttons in tool bar
		JToolBar jtbTools = new JToolBar(m_sTitle);
		jtbTools.setFloatable(false);
		jtbTools.setRollover(true);
		jtbTools.add(jbHome);
		jtbTools.add(m_jbBack);
		jtbTools.add(m_jbForward);

		// Table of contents pane
		JEditorPane jepContents = new JEditorPane();
		jepContents.setEditable(false);
		jepContents.setPreferredSize(new Dimension(300, 400));

		jepContents.addHyperlinkListener(new HyperlinkListener()
		{
			@Override
			public void hyperlinkUpdate(HyperlinkEvent evt)
			{
				try
				{
					if (evt.getEventType() == HyperlinkEvent.EventType.ACTIVATED)
					{
						jepTopic.setPage(evt.getURL());
						m_history.visit(evt.getURL());
					}
				}
				catch (IOException ex)
				{
					JOptionPane.showMessageDialog(FHelp.this,
		                MessageFormat.format(RB.getString("FHelp.NoLocateUrl.message"), evt.getURL()), m_sTitle,
		                JOptionPane.ERROR_MESSAGE);
				}
			}
		});

		try
		{
			jepContents.setPage(toc);
		}
		catch (IOException ex)
		{
			JOptionPane.showMessageDialog(FHelp.this,
			    MessageFormat.format(RB.getString("FHelp.NoLocateUrl.message"), toc), m_sTitle,
			    JOptionPane.ERROR_MESSAGE);
			return;
		}

		try
		{
			m_home = home;
			jepTopic.setPage(m_home);
		}
		catch (IOException ex)
		{
			JOptionPane.showMessageDialog(FHelp.this,
			    MessageFormat.format(RB.getString("FHelp.NoLocateUrl.message"), m_home), m_sTitle,
			    JOptionPane.ERROR_MESSAGE);
			return;
		}

		// Make panes scrollable
		JScrollPane jspTopic = new JScrollPane(jepTopic);
		JScrollPane jspContents = new JScrollPane(jepContents);

		// Put panes into a horizontal split pane
		JSplitPane jspHelp = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, jspContents, jspTopic);
		jspHelp.setResizeWeight(0.0);
		jspHelp.resetToPreferredSizes();
		jspHelp.setBorder(new CompoundBorder(new EtchedBorder(), new EmptyBorder(3, 3, 3, 3)));

		// Put it all together
		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jtbTools, BorderLayout.NORTH);
		getContentPane().add(jspHelp, BorderLayout.CENTER);

		addWindowListener(new WindowAdapter()
		{
			@Override
			public void windowClosing(WindowEvent evt)
			{
				setVisible(false);
			}
		});

		setIconImage(Toolkit.getDefaultToolkit().createImage(getClass().getResource(RB.getString("FHelp.Icon.image"))));

		pack();
	}

	/**
	 * Show the help window?
	 * 
	 * @param bShow If true show the help window otherwise hide it
	 */
	@Override
	public void setVisible(boolean bShow)
	{
		if (bShow)
		{
			// If the frame was minimized during its last display it won't be after this
			setState(Frame.NORMAL);
		}

		super.setVisible(bShow);
	}

	/**
	 * Notifies the help that the history status has changed and it should adjust its buttons accordingly.
	 * 
	 * @param evt The HistoryEvent
	 */
	@Override
	public void historyStatusChanged(HistoryEvent evt)
	{
		m_jbBack.setEnabled(evt.isBackAvailable());
		m_jbForward.setEnabled(evt.isForwardAvailable());
	}
}
