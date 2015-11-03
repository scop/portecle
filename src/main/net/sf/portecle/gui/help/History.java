/*
 * History.java
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

package net.sf.portecle.gui.help;

import java.net.URL;
import java.util.LinkedList;
import java.util.Vector;

/**
 * Implements a navigation history for help.
 */
/* package private */class History
{
	/** Visited pages */
	private final Vector<URL> m_vHistory = new Vector<>();

	/** Current navigation location */
	private int m_iCurrent;

	/** Can we navigate forward from the current history position? */
	private boolean m_bForward;

	/** Can we navigate back from the current history position */
	private boolean m_bBack;

	/** History listeners */
	private LinkedList<HistoryEventListener> listeners;

	/**
	 * Constructs a new History specifying the first URL.
	 * 
	 * @param start the first page in the m_vHistory
	 */
	public History(URL start)
	{
		m_vHistory.add(start);
		m_iCurrent = 0;
		m_bForward = false;
		m_bBack = false;
	}

	/**
	 * Clears the History of all but the starting document.
	 */
	public void clear()
	{
		URL start = m_vHistory.get(0);

		m_vHistory.clear();
		m_vHistory.add(start);
		m_iCurrent = 0;
		m_bForward = false;
		m_bBack = false;
		fireHistoryEvent();
	}

	/**
	 * Adds a new page to the history and fires a HistoryEvent if the History's status has changed.
	 * 
	 * @param newPage the new page to add to the history
	 */
	public void visit(URL newPage)
	{
		// Only add page to history if it isn't the current page in the history
		if (newPage.toExternalForm().equals(m_vHistory.get(m_iCurrent).toExternalForm()))
		{
			// New page same as current page so ignore
			return;
		}

		// At end of history...
		if (!m_bForward)
		{
			m_vHistory.add(newPage);
			m_iCurrent++;
		}
		// Not at end of history...
		else
		{
			// Loop off history after the current page
			int iRemove = m_vHistory.size() - (m_iCurrent + 1);

			for (int iCnt = 0; iCnt < iRemove; iCnt++)
			{
				m_vHistory.remove(m_vHistory.size() - 1);
			}

			// Add new page to end of history
			m_vHistory.add(newPage);
			m_iCurrent++;
		}

		m_bBack = (m_iCurrent != 0);

		m_bForward = (m_iCurrent + 1 != m_vHistory.size());

		fireHistoryEvent();
	}

	/**
	 * Returns the previous URL in the History and fires a HistoryEvent if the History status has perhaps changed.
	 * 
	 * @return The previous URL in the History or null if there is none
	 */
	public URL goBack()
	{
		if (!m_bBack)
		{
			return null;
		}

		URL page = m_vHistory.get(--m_iCurrent);

		if (m_iCurrent == 0)
		{
			m_bBack = false;
			m_bForward = true;
			fireHistoryEvent();
		}
		else if (!m_bForward)
		{
			m_bForward = true;
			fireHistoryEvent();
		}

		return page;
	}

	/**
	 * Returns the next URL in the History and fires a HistoryEvent if the History status has perhaps changed.
	 * 
	 * @return The next URL in the History or null if there is none
	 */
	public URL goForward()
	{
		if (!m_bForward)
		{
			return null;
		}

		URL page = m_vHistory.get(++m_iCurrent);

		if (m_iCurrent == m_vHistory.size() - 1)
		{
			m_bForward = false;
			m_bBack = true;
			fireHistoryEvent();
		}
		else if (!m_bBack)
		{
			m_bBack = true;
			fireHistoryEvent();
		}

		return page;
	}

	/**
	 * Adds a HistoryEventListener to the History.
	 * 
	 * @param listener The HistoryEventListener to add
	 */
	public synchronized void addHistoryEventListener(HistoryEventListener listener)
	{
		if (listeners == null)
		{
			listeners = new LinkedList<>();
		}

		listeners.add(listener);
	}

	/**
	 * Removes a HistoryEventListener from the History.
	 * 
	 * @param listener The HistoryEventListener to remove
	 */
	public synchronized void removeHistoryEventListener(HistoryEventListener listener)
	{
		if (listeners == null)
		{
			listeners = new LinkedList<>();
		}
		else
		{
			listeners.remove(listener);
		}
	}

	/**
	 * Fires a HistoryEvent to registered listeners notifying them of a change in the History's status.
	 */
	private synchronized void fireHistoryEvent()
	{
		if (listeners != null && !listeners.isEmpty())
		{
			HistoryEvent evt = new HistoryEvent(this, m_bBack, m_bForward);
			for (HistoryEventListener listener : listeners)
			{
				listener.historyStatusChanged(evt);
			}
		}
	}
}
