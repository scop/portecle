/*
 * ProviderUtil.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Ville Skyttä, ville.skytta@iki.fi
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

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collection;

/**
 * Provides security provider utility methods.
 */
public final class ProviderUtil
{
	/**
	 * Private to prevent construction.
	 */
	private ProviderUtil()
	{
		// Nothing to do
	}

	/**
	 * Get the PKCS #11 <code>Provider</code>s available on the system.
	 * 
	 * @return the (possibly empty) collection of available PKCS #11 <code>Provider</code>s
	 */
	public static Collection<Provider> getPkcs11Providers()
	{
		ArrayList<Provider> p11s = new ArrayList<>();
		for (Provider prov : Security.getProviders())
		{
			String pName = prov.getName();
			// Is it a PKCS #11 provider?
			/*
			 * TODO: is there a better way to find out? Could try instanceof sun.security.pkcs11.SunPKCS11 but that
			 * would require the class to be available?
			 */
			if (pName.startsWith("SunPKCS11-"))
			{
				p11s.add(prov);
			}
		}
		return p11s;
	}
}
