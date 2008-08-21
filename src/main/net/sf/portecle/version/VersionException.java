/*
 * VersionException.java
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

package net.sf.portecle.version;

/**
 * Represents a version exception.
 */
public class VersionException
    extends Exception
{
	/**
	 * Creates a new VersionException.
	 */
	public VersionException()
	{
		super();
	}

	/**
	 * Creates a new VersionException with the specified message.
	 * 
	 * @param sMessage Exception message
	 */
	public VersionException(String sMessage)
	{
		super(sMessage);
	}

	/**
	 * Creates a new VersionException with the specified message and cause throwable.
	 * 
	 * @param causeThrowable The throwable that caused this exception to be thrown
	 * @param sMessage Exception message
	 */
	public VersionException(String sMessage, Throwable causeThrowable)
	{
		super(sMessage, causeThrowable);
	}

	/**
	 * Creates a new VersionException with the specified cause throwable.
	 * 
	 * @param causeThrowable The throwable that caused this exception to be thrown
	 */
	public VersionException(Throwable causeThrowable)
	{
		super(causeThrowable);
	}
}
