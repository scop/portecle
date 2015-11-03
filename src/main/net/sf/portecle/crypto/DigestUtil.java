/*
 * DigestUtil.java
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

package net.sf.portecle.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;

import net.sf.portecle.FPortecle;
import net.sf.portecle.StringUtil;

/**
 * Provides utility methods for the creation of message digests.
 */
public final class DigestUtil
{
	/**
	 * Private to prevent construction.
	 */
	private DigestUtil()
	{
		// Nothing to do
	}

	/**
	 * Get the digest of a message as a formatted String.
	 * 
	 * @param bMessage The message to digest
	 * @param digestType The message digest algorithm
	 * @return The message digest
	 * @throws CryptoException If there was a problem generating the message digest
	 */
	public static String getMessageDigest(byte[] bMessage, DigestType digestType)
	    throws CryptoException
	{
		// Create message digest object using the supplied algorithm
		MessageDigest messageDigest;
		try
		{
			messageDigest = MessageDigest.getInstance(digestType.name());
		}
		catch (NoSuchAlgorithmException ex)
		{
			throw new CryptoException(
			    MessageFormat.format(FPortecle.RB.getString("NoCreateDigest.exception.message"), digestType), ex);
		}

		// Create raw message digest
		byte[] bFingerPrint = messageDigest.digest(bMessage);

		// Return the formatted message digest
		StringBuilder sb = StringUtil.toHex(bFingerPrint, 2, ":");
		return sb.toString();
	}
}
