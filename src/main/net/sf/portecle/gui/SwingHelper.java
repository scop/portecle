/*
 * SwingHelper.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2007-2014 Ville Skyttä, ville.skytta@iki.fi
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

package net.sf.portecle.gui;

import static net.sf.portecle.FPortecle.LOG;

import java.awt.Component;
import java.awt.Window;
import java.lang.reflect.InvocationTargetException;
import java.util.logging.Level;

import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.text.JTextComponent;

/**
 * Swing helper.
 */
public final class SwingHelper
{
	/** Not needed. */
	private SwingHelper()
	{
		// Ignored
	}

	/**
	 * Makes the given Window visible and waits for it to return.
	 * 
	 * @param window The window
	 */
	public static void showAndWait(final Window window)
	{
		if (SwingUtilities.isEventDispatchThread())
		{
			window.setVisible(true);
		}
		else
		{
			try
			{
				SwingUtilities.invokeAndWait(new Runnable()
				{
					@Override
					public void run()
					{
						window.setVisible(true);
					}
				});
			}
			catch (InterruptedException | InvocationTargetException e)
			{
				LOG.log(Level.WARNING, "Error setting window visible", e); // TODO?
			}
		}
	}

	/**
	 * Select all text in a text component and focus it.
	 * 
	 * @param component the text component
	 */
	public static void selectAndFocus(JComponent component)
	{
		JTextComponent textComponent = null;
		if (component instanceof JTextComponent)
		{
			textComponent = (JTextComponent) component;
		}
		if (component instanceof JComboBox)
		{
			Component editorComponent = ((JComboBox<?>) component).getEditor().getEditorComponent();
			if (editorComponent instanceof JTextComponent)
			{
				textComponent = (JTextComponent) editorComponent;
			}
		}
		if (textComponent != null)
		{
			textComponent.select(0, textComponent.getText().length());
		}
		component.requestFocusInWindow();
	}

	/**
	 * Shows a simple yes/no confirmation dialog, with the "no" option selected by default. This method exists only
	 * because there's apparently no easy way to accomplish that with JOptionPane's static helper methods.
	 * 
	 * @param parentComponent
	 * @param message
	 * @param title
	 * @see JOptionPane#showConfirmDialog(Component, Object, String, int)
	 */
	public static int showConfirmDialog(Component parentComponent, Object message, String title)
	{
		String[] options = { "Yes", "No" };
		return JOptionPane.showOptionDialog(parentComponent, message, title, JOptionPane.YES_NO_OPTION,
		    JOptionPane.QUESTION_MESSAGE, null, options, options[1]);
	}
}
