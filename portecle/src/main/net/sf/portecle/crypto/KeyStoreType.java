/*
 * KeyStoreType.java
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

package net.sf.portecle.crypto;

import java.io.InvalidObjectException;
import java.io.ObjectStreamException;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.ResourceBundle;

/**
 * Type safe enumeration of keystore types supported by the KeyStoreUtil
 * class.
 */
public class KeyStoreType
{
    /** JCEKS keystore Type */
    public static final KeyStoreType JCEKS = new KeyStoreType("JCEKS", true);

    /** JKS keystore Type */
    public static final KeyStoreType JKS = new KeyStoreType("JKS", true);

    /** PKCS #11 keystore Type */
    public static final KeyStoreType PKCS11 = new KeyStoreType("PKCS11",false);

    /** PKCS #12 keystore Type */
    public static final KeyStoreType PKCS12 = new KeyStoreType("PKCS12",false);

    /** BKS keystore Type */
    public static final KeyStoreType BKS = new KeyStoreType("BKS", true);

    /** UBER keystore Type */
    public static final KeyStoreType UBER = new KeyStoreType("UBER", true);

    /** String-to-type map */
    private static final HashMap TYPE_MAP = new HashMap();
    static {
        TYPE_MAP.put(JKS.toString(),    JKS);
        TYPE_MAP.put(JCEKS.toString(),  JCEKS);
        TYPE_MAP.put(PKCS11.toString(), PKCS11);
        TYPE_MAP.put(PKCS12.toString(), PKCS12);
        TYPE_MAP.put(BKS.toString(),    BKS);
        TYPE_MAP.put(UBER.toString(),   UBER);
    }

    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/crypto/resources");

    /** Stores keystore type name */
    private final String m_sType;

    /** Whether the keystore type supports creation dates */
    private final boolean m_bCreationDate;

    /**
     * Construct a KeyStoreType.
     * Private to prevent construction from outside this class.
     *
     * @param sType Keystore type
     * @param bCreationDate Whether the keystore supports creation dates
     */
    private KeyStoreType(String sType, boolean bCreationDate)
    {
        m_sType = sType;
        m_bCreationDate = bCreationDate;
    }

    /**
     * Gets a KeyStoreType corresponding to the given type String.
     *
     * @param sType the keystore type name
     * @return the corresponding KeyStoreType
     * @throws CryptoException if the type is not known
     */
    public static KeyStoreType getInstance(String sType)
        throws CryptoException
    {
        KeyStoreType kst = (KeyStoreType) TYPE_MAP.get(sType);
        if (kst == null) {
            throw new CryptoException(
                MessageFormat.format(
                    m_res.getString("NoResolveKeystoretype.exception.message"),
                    new String[]{sType}));
        }
        return kst;
    }

    /**
     * Does the keystore type support creation dates?
     *
     * @return true if creation dates are supported, false otherwise
     */
    public boolean supportsCreationDate()
    {
        return m_bCreationDate;
    }

    /**
     * Resolve the KeyStoreType Object.
     *
     * @return The resolved KeyStoreType object
     * @throws ObjectStreamException if the KeyStoreType could not be resolved
     */
    private Object readResolve() throws ObjectStreamException
    {
        try {
            return getInstance(m_sType);
        }
        catch (CryptoException e) {
            throw new InvalidObjectException(e.getMessage());
        }
    }

    /**
     * Return string representation of keystore type compatible with the JCE.
     *
     * @return String representation of a keystore type
     */
    public String toString()
    {
        return m_sType;
    }

    /**
     * Return a "pretty", human readable representation of the keystore type.
     *
     * @return human readable String representation of the keystore type
     */
    public String toPrettyString()
    {
        if (equals(PKCS11)) {
            return "PKCS #11";
        }
        if (equals(PKCS12)) {
            return "PKCS #12";
        }
        return toString();
    }
}
