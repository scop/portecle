/*
 * AlgorithmType.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2006-2008 Ville Skyttä, ville.skytta@iki.fi
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

import java.util.HashMap;

/**
 * Algorithm type. Enum constant names are compatible with JCA standard names.
 * 
 * @see <a href="http://download.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html">JCA Standard
 *      Names</a>
 */
public enum AlgorithmType
{
	DSA("1.2.840.10040.4.1"),
	RSA("1.2.840.113549.1.1.1");

	/** OID-to-type map */
	private static final HashMap<String, AlgorithmType> OID_MAP = new HashMap<>();

	static
	{
		for (AlgorithmType at : values())
		{
			OID_MAP.put(at.oid, at);
		}
	}

	private final String oid;

	private AlgorithmType(String oid)
	{
		this.oid = oid;
	}

	/**
	 * Gets an AlgorithmType corresponding to the given object identifier.
	 * 
	 * @param oid the object identifier
	 * @return the corresponding AlgorithmType, <code>null</code> if unknown
	 */
	public static AlgorithmType valueOfOid(String oid)
	{
		return OID_MAP.get(oid);
	}

	/**
	 * Gets a string representation of algorithm type corresponding to the given object identifier.
	 * 
	 * @param oid the object identifier
	 * @return the corresponding algorithm type as string, <code>oid</code> itself if unknown
	 */
	public static String toString(String oid)
	{
		AlgorithmType type = valueOfOid(oid);
		if (type != null)
		{
			return type.toString();
		}
		return oid;
	}
}
