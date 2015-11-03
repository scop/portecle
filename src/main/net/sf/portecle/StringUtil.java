/*
 * StringUtil.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2011-2014 Ville Skyttä, ville.skytta@iki.fi
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

package net.sf.portecle;

import java.math.BigInteger;
import java.util.Locale;

import org.bouncycastle.asn1.ASN1Integer;

/**
 * String utilities.
 * 
 * @author Ville Skyttä
 */
public class StringUtil
{
	/**
	 * Convert the supplied object to hex characters sub-divided by spaces every given number of characters, and
	 * left-padded with zeros to fill group size.
	 * 
	 * @param obj Object (byte array, BigInteger, ASN1Integer)
	 * @param groupSize number of characters to group hex characters by
	 * @param separator grouping separator
	 * @return Hex string
	 * @throws IllegalArgumentException if obj is not a BigInteger, byte array, or an ASN1Integer, or groupSize &lt; 0
	 */
	public static StringBuilder toHex(Object obj, int groupSize, String separator)
	{
		if (groupSize < 0)
		{
			throw new IllegalArgumentException("Group size must be >= 0");
		}
		BigInteger bigInt;
		if (obj instanceof BigInteger)
		{
			bigInt = (BigInteger) obj;
		}
		else if (obj instanceof byte[])
		{
			bigInt = new BigInteger(1, (byte[]) obj);
		}
		else if (obj instanceof ASN1Integer)
		{
			bigInt = ((ASN1Integer) obj).getValue();
		}
		else
		{
			throw new IllegalArgumentException(
			    "Don't know how to convert " + obj.getClass().getName() + " to a hex string");
		}

		// Convert to hex

		StringBuilder sb = new StringBuilder(bigInt.toString(16).toUpperCase(Locale.ENGLISH));

		// Left-pad if asked and necessary

		if (groupSize != 0)
		{
			int len = groupSize - (sb.length() % groupSize);
			if (len != groupSize)
			{
				for (int i = 0; i < len; i++)
				{
					sb.insert(0, '0');
				}
			}
		}

		// Place separator at every groupSize characters

		if (sb.length() > groupSize && !separator.isEmpty())
		{
			for (int i = groupSize; i < sb.length(); i += groupSize + separator.length())
			{
				sb.insert(i, separator);
			}
		}

		return sb;
	}
}
