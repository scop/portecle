/*
 * KeyStoreType.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004-2008 Ville Skyttä, ville.skytta@iki.fi
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

package net.sf.portecle.crypto;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * KeyStore type. Enum constant names are compatible with JCA names.
 * 
 * @see <a href="http://java.sun.com/javase/6/docs/technotes/guides/security/StandardNames.html">JCA Standard
 *      Names</a>
 */
public enum KeyStoreType
{
	/** JKS keystore Type */
	JKS("JKS", true, new String[] { "jks" }),
	/** PKCS #12 keystore Type */
	PKCS12("PKCS #12", false, new String[] { "p12", "pfx" }),
	/** JCEKS keystore Type */
	JCEKS("JCEKS", true, new String[] { "jceks" }),
	/** Case sensitive JKS keystore Type */
	CaseExactJKS("JKS (case sensitive)", true, new String[] { "jks" }),
	/** BKS keystore Type */
	BKS("BKS", true, new String[] { "bks" }),
	/** UBER keystore Type */
	UBER("UBER", true, new String[] { "ubr" }),
	/** GKR keystore Type */
	GKR("GKR", true, new String[] { "gkr" }),
	/** PKCS #11 keystore Type */
	PKCS11("PKCS #11", false, new String[0]);

	/** Keystore "pretty" name */
	private final String prettyName;

	/** Whether the keystore type supports creation dates */
	private final boolean supportsCreationDate;

	/** Associated filename extensions */
	private final Set<String> filenameExtensions;

	/**
	 * Construct a KeyStoreType. Private to prevent construction from outside this class.
	 * 
	 * @param sType Keystore type
	 * @param supportsCreationDates Whether the keystore supports creation dates
	 * @param filenameExtensions associated filename extensions
	 */
	private KeyStoreType(String prettyName, boolean supportsCreationDate, String[] filenameExtensions)
	{
		this.prettyName = prettyName;
		this.supportsCreationDate = supportsCreationDate;
		switch (filenameExtensions.length)
		{
			case 0:
				this.filenameExtensions = Collections.emptySet();
				break;
			case 1:
				this.filenameExtensions = Collections.singleton(filenameExtensions[0]);
				break;
			default:
				LinkedHashSet<String> exts = new LinkedHashSet<String>(filenameExtensions.length);
				Collections.addAll(exts, filenameExtensions);
				this.filenameExtensions = Collections.unmodifiableSet(exts);
		}
	}

	/**
	 * Does the keystore type support creation dates?
	 * 
	 * @return true if creation dates are supported, false otherwise
	 */
	public boolean supportsCreationDate()
	{
		return supportsCreationDate;
	}

	/**
	 * Common filename extensions associated with this type.
	 * 
	 * @return filename extensions (without leading dot, in lowercase), empty if not applicable
	 */
	public Set<String> getFilenameExtensions()
	{
		return filenameExtensions;
	}

	/**
	 * Return string representation of keystore type.
	 * 
	 * @return String representation of a keystore type
	 */
	@Override
	public String toString()
	{
		return prettyName;
	}
}
