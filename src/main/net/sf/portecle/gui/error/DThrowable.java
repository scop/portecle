/*
 * DThrowable.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2008 Ville Skyttä, ville.skytta@iki.fi
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

import static net.sf.portecle.FPortecle.RB;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.text.MessageFormat;
import java.util.Locale;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import net.sf.portecle.PortecleJDialog;
import net.sf.portecle.gui.SwingHelper;

/**
 * Modal dialog for displaying a Throwable message with the option to display the stack trace.
 */
public class DThrowable
    extends PortecleJDialog
{
	/** Stores Throwable to display */
	private final Throwable m_throwable;

	/**
	 * Exception message parts that may indicate that the culprit for the Throwable is lack of unrestricted JCE policy
	 * files.
	 */
	private final static String[] POLICY_PROBLEM_HINTS = { "unsupported keysize", "illegal key size", };

	/**
	 * Creates new DThrowable dialog with the given title.
	 * 
	 * @param parent Parent window
	 * @param title Dialog title; if null, application default for DThrowables is used
	 * @param throwable Throwable to display
	 */
	public DThrowable(Window parent, String title, Throwable throwable)
	{
		super(parent, true);
		setTitle((title == null) ? RB.getString("DThrowable.Title") : title);
		m_throwable = throwable;
		initComponents();
	}

	/**
	 * Create, show, and wait for a new DThrowable dialog.
	 * 
	 * @param parent Parent window
	 * @param title Dialog title; if null, application default for DThrowables is used
	 * @param throwable Throwable to display
	 */
	public static void showAndWait(Window parent, String title, Throwable throwable)
	{
		DThrowable dt = new DThrowable(parent, title, throwable);
		dt.setLocationRelativeTo(parent);
		SwingHelper.showAndWait(dt);
	}

	/**
	 * Initialize the dialog's GUI components.
	 */
	private void initComponents()
	{
		JPanel jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));

		JButton jbDetails = new JButton(RB.getString("DThrowable.jbDetails.text"));
		jbDetails.setMnemonic(RB.getString("DThrowable.jbDetails.mnemonic").charAt(0));

		jbDetails.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent evt)
			{
				showThrowableDetail();
			}
		});

		JButton jbOK = getOkButton(true);

		jpButtons.add(jbOK);
		jpButtons.add(jbDetails);

		JPanel jpThrowable = new JPanel(new FlowLayout(FlowLayout.CENTER));
		jpThrowable.setBorder(new EmptyBorder(5, 5, 5, 5));

		String text = m_throwable.toString();

		// Find out if this problem maybe due to missing unrestricted JCE policy files. Ugly? Definitely.
		// Better ways to detect this are welcome...

		boolean maybePolicyProblem = false;
		Throwable t = m_throwable;
		while (!maybePolicyProblem && t != null)
		{
			String msg = t.getMessage();
			if (msg != null)
			{
				msg = msg.toLowerCase(Locale.US);
				for (String hint : POLICY_PROBLEM_HINTS)
				{
					if (msg.contains(hint))
					{
						maybePolicyProblem = true;
						break;
					}
				}
			}
			t = t.getCause();
		}
		if (maybePolicyProblem)
		{
			text = "<html>" + text + MessageFormat.format(RB.getString("DThrowable.jpThrowable.policy.text"),
			    new File(System.getProperty("java.home"), "lib" + File.separator + "security"));
		}

		jpThrowable.add(new JLabel(text));

		getContentPane().add(jpThrowable, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		getRootPane().setDefaultButton(jbOK);

		initDialog();
	}

	/**
	 * Shows the Throwable Detail dialog.
	 */
	private void showThrowableDetail()
	{
		DThrowableDetail dThrowableDetail = new DThrowableDetail(this, m_throwable);
		dThrowableDetail.setLocationRelativeTo(this);
		SwingHelper.showAndWait(dThrowableDetail);
	}
}
