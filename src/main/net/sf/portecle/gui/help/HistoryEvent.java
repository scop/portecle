/*
 * HistoryEvent.java
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

import java.util.EventObject;

/**
 * Defines an event for reporting status changes in a History.
 */
/* package private */class HistoryEvent
    extends EventObject
{
	/** Is history back navigable? */
	private final boolean m_bBackAvailable;

	/** Is history forward navigable? */
	private final boolean m_bForwardAvailable;

	/**
	 * Constructs a new HistoryEvent.
	 * 
	 * @param eventSource The source of the event
	 * @param bBackAvailable Whether there is a document in the history before the current document
	 * @param bForwardAvailable Whether there is a document in the history after the current document
	 */
	public HistoryEvent(Object eventSource, boolean bBackAvailable, boolean bForwardAvailable)
	{
		super(eventSource);
		m_bBackAvailable = bBackAvailable;
		m_bForwardAvailable = bForwardAvailable;
	}

	/**
	 * Is there is a document in the history before the current document?
	 * 
	 * @return True if there is a document in the history before the current document
	 */
	public boolean isBackAvailable()
	{
		return m_bBackAvailable;
	}

	/**
	 * Is there is a document in the history after the current document?
	 * 
	 * @return True if there is a document in the history after the current document
	 */
	public boolean isForwardAvailable()
	{
		return m_bForwardAvailable;
	}
}
