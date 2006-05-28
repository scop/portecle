/*
 * AlgorithmType.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2006 Ville Skyttä, ville.skytta@iki.fi
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

import java.io.ObjectStreamException;
import java.util.HashMap;

/**
 * Type safe enumeration of algorithm types.
 */
public class AlgorithmType
{
    /** DSA algorithm type */
    public static final AlgorithmType DSA = new AlgorithmType("DSA");

    /** RSA algorithm type */
    public static final AlgorithmType RSA = new AlgorithmType("RSA");

    /** OID-to-type map */
    private static final HashMap OID_MAP = new HashMap();
    static {
        OID_MAP.put("1.2.840.10040.4.1", DSA);
        OID_MAP.put("1.2.840.113549.1.1.1", RSA);
    }

    /** Stores algorithm type name */
    private final String m_sType;

    /**
     * Construct a AlgorithmType.  Private to prevent construction from outside
     * this class.
     *
     * @param sType Algorithm type
     */
    private AlgorithmType(String sType)
    {
        m_sType = sType;
    }

    /**
     * Gets an AlgorithmType corresponding to the given OID.
     *
     * @param oid the object identifier
     * @return the corresponding AlgorithmType
     */
    public static AlgorithmType forOid(String oid)
    {
        AlgorithmType at = (AlgorithmType) OID_MAP.get(oid);
        return at == null ? new AlgorithmType(oid) : at;
    }

    /**
     * Resolve the AlgorithmType Object.
     *
     * @return The resolved AlgorithmType object
     * @throws ObjectStreamException if the AlgorithmType could not be resolved
     */
    private Object readResolve()
    {
        if (m_sType.equals(DSA.toString())) {
            return DSA;
        }
        else if (m_sType.equals(RSA.toString())) {
            return RSA;
        }
        else {
            return new AlgorithmType(m_sType);
        }
    }

    /**
     * Return string representation of algorithm type.
     *
     * @return String representation of a algorithm type
     */
    public String toString()
    {
        return m_sType;
    }
}
