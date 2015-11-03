/*
 * KeyStoreType.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004-2013 Ville Skyttä, ville.skytta@iki.fi
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
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * KeyStore type. Enum constant names are compatible with JCA names.
 * 
 * @see <a href="http://download.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html">JCA Standard
 *      Names</a>
 */
public enum KeyStoreType
{
    /** JKS keystore Type */
	JKS(null, "JKS", true, true, new String[] { "jks" }),
	/** PKCS #12 keystore Type */
	PKCS12(null, "PKCS #12", false, false, new String[] { "p12", "pfx" }),
	/** JCEKS keystore Type */
	JCEKS(null, "JCEKS", true, true, new String[] { "jceks" }),
	/** Case sensitive JKS keystore Type */
	CaseExactJKS(null, "JKS (case sensitive)", true, true, new String[] { "jks" }),
	/** BKS keystore Type */
	BKS(null, "BKS", true, true, new String[] { "bks" }),
	/** BKS-V1 keystore Type */
	BKS_V1("BKS-V1", "BKS-V1", true, true, new String[] { "bks" }),
	/** UBER keystore Type */
	UBER(null, "UBER", true, true, new String[] { "ubr" }),
	/** GKR keystore Type */
	GKR(null, "GKR", true, true, new String[] { "gkr" }),
	/** PKCS #11 keystore Type */
	PKCS11(null, "PKCS #11", false, true, new String[0]);

	/** Keystore type name */
	private final String typeName;

	/** Keystore "pretty" name */
	private final String prettyName;

	/** Whether the keystore type provides useful values for entry creation dates */
	private final boolean entryCreationDateUseful;

	/** Whether the keystore supports entry passwords */
	private final boolean entryPasswordSupported;

	/** Associated filename extensions */
	private final Set<String> filenameExtensions;

	/**
	 * Construct a KeyStoreType. Private to prevent construction from outside this class.
	 * 
	 * @param typeName
	 * @param prettyName
	 * @param entryCreationDateUseful Whether the keystore's creation dates have useful data
	 * @param entryPasswordSupported Whether entry passwords are supported
	 * @param filenameExtensions associated filename extensions
	 */
	private KeyStoreType(String typeName, String prettyName, boolean entryCreationDateUseful,
	    boolean entryPasswordSupported, String[] filenameExtensions)
	{
		this.typeName = (typeName == null) ? name() : typeName;
		this.prettyName = prettyName;
		this.entryCreationDateUseful = entryCreationDateUseful;
		this.entryPasswordSupported = entryPasswordSupported;
		switch (filenameExtensions.length)
		{
			case 0:
				this.filenameExtensions = Collections.emptySet();
				break;
			case 1:
				this.filenameExtensions = Collections.singleton(filenameExtensions[0]);
				break;
			default:
				LinkedHashSet<String> exts = new LinkedHashSet<>(filenameExtensions.length);
				Collections.addAll(exts, filenameExtensions);
				this.filenameExtensions = Collections.unmodifiableSet(exts);
		}
	}

	/**
	 * Name of the keystore type used for creating a new instance.
	 */
	public String getTypeName()
	{
		return typeName;
	}

	/**
	 * Does the keystore type provide useful values for entry creation dates? Some keystores return the keystore load
	 * time as creation date for all entries, this is not considered useful by this class.
	 * 
	 * @return true if creation dates are useful, false otherwise
	 */
	public boolean isEntryCreationDateUseful()
	{
		return entryCreationDateUseful;
	}

	/**
	 * Does the keystore type support passwords for entries?
	 * 
	 * @return true if entry passwords are supported, false otherwise
	 */
	public boolean isEntryPasswordSupported()
	{
		return entryPasswordSupported;
	}

	/**
	 * Common filename extensions associated with this type.
	 * 
	 * @return filename extensions (without leading dot, in lower case), empty if not applicable
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

	/**
	 *
	 */
	public static KeyStoreType valueOfType(String typeName)
	{
		return valueOf(typeName.replaceAll("-", "_"));
	}

	/**
	 * Get set of all known keystore filename extensions.
	 */
	public static Set<String> getKeyStoreFilenameExtensions()
	{
		HashSet<String> exts = new HashSet<>();
		for (KeyStoreType ksType : values())
		{
			exts.addAll(ksType.getFilenameExtensions());
		}
		return exts;
	}
}
