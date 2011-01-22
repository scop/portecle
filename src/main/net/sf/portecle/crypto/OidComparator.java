/*
 * OidComparator.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2011 Ville Skyttä, ville.skytta@iki.fi
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

import java.util.Arrays;
import java.util.Comparator;

/**
 * Comparator for OID string values.
 */
public class OidComparator
    implements Comparator<String>
{
	@Override
	public int compare(String o1, String o2)
	{
		int longest = 0;

		String[] bits1 = o1.split("\\.");
		int[] lengths1 = new int[bits1.length];
		String[] bits2 = o2.split("\\.");
		int[] lengths2 = new int[bits2.length];

		for (int i = 0; i < bits1.length; i++)
		{
			lengths1[i] = bits1[i].length();
			longest = Math.max(longest, lengths1[i]);
		}
		for (int i = 0; i < bits2.length; i++)
		{
			lengths2[i] = bits2[i].length();
			longest = Math.max(longest, lengths2[i]);
		}

		for (int i = 0; i < bits1.length; i++)
		{
			if (lengths1[i] < longest)
			{
				bits1[i] = String.format("%" + (longest - lengths1[i]) + "s", bits1[i]);
			}
		}
		for (int i = 0; i < bits2.length; i++)
		{
			if (lengths2[i] < longest)
			{
				bits2[i] = String.format("%" + (longest - lengths2[i]) + "s", bits2[i]);
			}
		}

		return Arrays.toString(bits1).compareTo(Arrays.toString(bits2));
	}
}
