/*
 * KeyStoreType.java
 *
 * Copyright (C) 2004 Wayne Grant
 * waynedgrant@hotmail.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * (This program is distributed in the hope that it will be useful,
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
 * Type safe enumeration of KeyStore Types supported by the KeyStoreUtil class.
 */
public class KeyStoreType extends Object
{
    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/crypto/resources");

    /** Stores KeyStore Type name */
    private final String m_sType;

    /** JCEKS KeyStore Type JCE String */
    private static final String JCEKS_STR = "JCEKS";

    /** JKS KeyStore Type JCE String */
    private static final String JKS_STR = "JKS";

    /** PKCS #12 KeyStore Type JCE String */
    private static final String PKCS12_STR = "PKCS12";

    /** BKS KeyStore Type JCE String */
    private static final String BKS_STR = "BKS";

    /** UBER KeyStore Type JCE String */
    private static final String UBER_STR = "UBER";

    /** JCEKS KeyStore Type */
    public static final KeyStoreType JCEKS = new KeyStoreType(JCEKS_STR);

    /** JKS KeyStore Type */
    public static final KeyStoreType JKS = new KeyStoreType(JKS_STR);

    /** PKCS #12 KeyStore Type */
    public static final KeyStoreType PKCS12 = new KeyStoreType(PKCS12_STR);

    /** BKS KeyStore Type */
    public static final KeyStoreType BKS = new KeyStoreType(BKS_STR);

    /** UBER KeyStore Type */
    public static final KeyStoreType UBER = new KeyStoreType(UBER_STR);

    /**
     * Construct a KeyStoreType.  Private to prevent construction from outside this
     * class.
     *
     * @param sType KeyStore type
     */
    private KeyStoreType(String sType)
    {
        m_sType = sType;
    }

    /**
     * Resolve the KeyStoreType Object.
     *
     * @return The resolved KeyStoreType object
     * @throws ObjectStreamException if the KeyStoreType could not be resolved
     */
    private Object readResolve() throws ObjectStreamException
    {
        if (m_sType.equals(JCEKS_STR))
        {
            return JCEKS;
        }
        else if (m_sType.equals(JKS_STR))
        {
            return JKS;
        }
        else if (m_sType.equals(PKCS12_STR))
        {
            return PKCS12;
        }
        else if (m_sType.equals(BKS_STR))
        {
            return BKS;
        }
        else if (m_sType.equals(UBER_STR))
        {
            return UBER;
        }
        else
        {
            throw new InvalidObjectException(MessageFormat.format(m_res.getString("NoResolveKeystoretype.exception.message"), new Object[]{m_sType}));
        }
    }

    /**
     * Return string representation of KeyStore Type compatible with the JCE.
     *
     * @return String representation of a KeyStore Type
     */
    public String toString()
    {
        return m_sType;
    }
}
