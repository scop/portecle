/*
 * KeyPairType.java
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

package net.sf.portecle.crypto;

import java.io.*;
import java.text.MessageFormat;
import java.util.ResourceBundle;

/**
 * Type safe enumeration of KeyPairTypes supported by the KeyPairUtil class.
 */
public class KeyPairType extends Object
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/crypto/resources");

    /** Stores KeyPairType name */
    private final String m_sType;

    /** RSA KeyPairType JCE String */
    private static final String RSA_STR = "RSA";

    /** DSA KeyPairType JCE String */
    private static final String DSA_STR = "DSA";

    /** RSA KeyPairType */
    public static final KeyPairType RSA = new KeyPairType(RSA_STR);

    /** DSA KeyPairType */
    public static final KeyPairType DSA = new KeyPairType(DSA_STR);

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
        if (m_sType.equals(RSA_STR))
        {
            return RSA;
        }
        else if (m_sType.equals(DSA_STR))
        {
            return DSA;
        }
        else
        {
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
