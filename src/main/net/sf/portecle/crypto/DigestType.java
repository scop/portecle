/*
 * DigestType.java
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

import java.io.InvalidObjectException;
import java.io.ObjectStreamException;
import java.text.MessageFormat;
import java.util.ResourceBundle;

/**
 * Type safe enumeration of Digest Types supported by the DigestUtil class.
 */
public class DigestType
{
    /** MD5 Digest Type */
    public static final DigestType MD5 = new DigestType("MD5");

    /** SHA-1 Digest Type */
    public static final DigestType SHA1 = new DigestType("SHA1");

    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/crypto/resources");

    /** Stores Digest Type name */
    private final String m_sType;

    /**
     * Construct a DigestType.  Private to prevent construction from outside
     * this class.
     *
     * @param sType Digest type
     */
    private DigestType(String sType)
    {
        m_sType = sType;
    }

    /**
     * Resolve the DigestType Object.
     *
     * @return The resolved DigestType object
     * @throws ObjectStreamException if the DigestType could not be resolved
     */
    private Object readResolve()
        throws ObjectStreamException
    {
        if (m_sType.equals(MD5.toString())) {
            return MD5;
        }
        else if (m_sType.equals(SHA1.toString())) {
            return SHA1;
        }
        else {
            throw new InvalidObjectException(MessageFormat.format(
                m_res.getString("NoResolveDigesttype.exception.message"),
                new Object[] { m_sType }));
        }
    }

    /**
     * Return string representation of Digest Type compatible with the JCE.
     *
     * @return String representation of a Digest Type
     */
    public String toString()
    {
        return m_sType;
    }
}
