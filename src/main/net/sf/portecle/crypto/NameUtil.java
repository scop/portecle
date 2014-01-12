/*
 * NameUtil.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2006-2012 Ville Skyttä, ville.skytta@iki.fi
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

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * Provides utility methods relating to X50* names.
 */
public final class NameUtil
{
	/**
	 * Private to prevent construction.
	 */
	private NameUtil()
	{
		// Nothing to do
	}

	/**
	 * Gets the common name from the given X500Name.
	 * 
	 * @param name the X.500 name
	 * @return the common name, null if not found
	 */
	public static String getCommonName(X500Name name)
	{
		if (name == null)
		{
			return null;
		}

		RDN[] rdns = name.getRDNs(BCStyle.CN);
		if (rdns.length == 0)
		{
			return null;
		}

		return rdns[0].getFirst().getValue().toString();
	}

	/**
	 * Gets the common name from the given X500Principal.
	 * 
	 * @param name the X.500 principal
	 * @return the common name, null if not found
	 */
	/* default */static String getCommonName(X500Principal name)
	{
		if (name == null)
		{
			return null;
		}

		return getCommonName(X500Name.getInstance(name.getEncoded()));
	}
}
