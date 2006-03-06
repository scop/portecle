/*
 * KeyPairType.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004 Ville Skyttä, ville.skytta@iki.fi
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
 * Type safe enumeration of KeyPairTypes supported by the KeyPairUtil class.
 */
public class KeyPairType
{
    /** RSA KeyPairType */
    public static final KeyPairType RSA = new KeyPairType("RSA");

    /** DSA KeyPairType */
    public static final KeyPairType DSA = new KeyPairType("DSA");

    /** ECDSA KeyPairType */
    public static final KeyPairType ECDSA = new KeyPairType("ECDSA");
    
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/crypto/resources");

    /** Stores KeyPairType name */
    private final String m_sType;

    /**
     * Construct a KeyPairType.  Private to prevent construction from outside
     * this class.
     *
     * @param sType Key pair type
     */
    private KeyPairType(String sType)
    {
        m_sType = sType;
    }

    /**
     * Resolve the KeyPairType Object.
     *
     * @return The resolved KeyPairType object
     * @throws ObjectStreamException if the KeyPairType could not be resolved
     */
    private Object readResolve () throws ObjectStreamException
    {
        if (m_sType.equals(RSA.toString())) {
            return RSA;
        }
        else if (m_sType.equals(DSA.toString())) {
            return DSA;
        }
        else if (m_sType.equals(ECDSA.toString())) {
            return ECDSA;
        }
        else {
            throw new InvalidObjectException(
                MessageFormat.format(
                    m_res.getString("NoResolveKeypairtype.exception.message"),
                    new Object[]{m_sType}));
        }
    }

    /**
     * Return string representation of KeyPairType compatible with the JCE.
     *
     * @return String representation of a KeyPairType
     */
    public String toString()
    {
        return m_sType;
    }
}
