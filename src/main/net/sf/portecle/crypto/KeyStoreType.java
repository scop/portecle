/*
 * KeyStoreType.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004-2006 Ville Skyttä, ville.skytta@iki.fi
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
import java.util.LinkedHashMap;
import java.util.ResourceBundle;

/**
 * Type safe enumeration of keystore types supported by the KeyStoreUtil
 * class.
 */
public class KeyStoreType
{
    /** JCEKS keystore Type */
    public static final KeyStoreType JCEKS = new KeyStoreType("JCEKS", true,
        false);

    /** JKS keystore Type */
    public static final KeyStoreType JKS = new KeyStoreType("JKS", true, false);

    /** PKCS #11 keystore Type */
    public static final KeyStoreType PKCS11 = new KeyStoreType("PKCS11",
        false, /* TODO: verify */false);

    /** PKCS #12 keystore Type */
    public static final KeyStoreType PKCS12 = new KeyStoreType("PKCS12",
        false, true);

    /** BKS keystore Type */
    public static final KeyStoreType BKS = new KeyStoreType("BKS", true, true);

    /** UBER keystore Type */
    public static final KeyStoreType UBER = new KeyStoreType("UBER", true,
        true);

    /** GKR keystore Type */
    public static final KeyStoreType GKR = new KeyStoreType("GKR", true, true);

    /** String-to-type map */
    private static final LinkedHashMap TYPE_MAP = new LinkedHashMap();
    static {
        // The order is the one in which getKnownTypes() should return these
        TYPE_MAP.put(JKS.toString(), JKS);
        TYPE_MAP.put(PKCS12.toString(), PKCS12);
        TYPE_MAP.put(JCEKS.toString(), JCEKS);
        TYPE_MAP.put(BKS.toString(), BKS);
        TYPE_MAP.put(UBER.toString(), UBER);
        TYPE_MAP.put(GKR.toString(), GKR);
        TYPE_MAP.put(PKCS11.toString(), PKCS11);
    }

    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/crypto/resources");

    /** Stores keystore type name */
    private final String m_sType;

    /** Whether the keystore type supports creation dates */
    private final boolean m_bCreationDate;

    /** Whether aliases in the keystore type are case sensitive */
    private final boolean m_bCaseSensitive;

    /**
     * Construct a KeyStoreType.
     * Private to prevent construction from outside this class.
     *
     * @param sType Keystore type
     * @param bCreationDate Whether the keystore supports creation dates
     * @param bCaseSensitive Whether aliases in the keystore are case sensitive 
     */
    private KeyStoreType(String sType, boolean bCreationDate,
        boolean bCaseSensitive)
    {
        m_sType = sType;
        m_bCreationDate = bCreationDate;
        m_bCaseSensitive = bCaseSensitive;
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
            throw new CryptoException(MessageFormat.format(
                m_res.getString("NoResolveKeystoretype.exception.message"),
                new String[] { sType }));
        }
        return kst;
    }

    /**
     * Gets known KeyStoreTypes.
     *
     * @return known keystore types
     */
    public static KeyStoreType[] getKnownTypes()
    {
        return (KeyStoreType[])
            TYPE_MAP.values().toArray(new KeyStoreType[TYPE_MAP.size()]);
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
     * Are aliases in the keystore case sensitive?
     * 
     * @return true if aliases are case sensitive, false otherwise
     */
    public boolean isCaseSensitive()
    {
        return m_bCaseSensitive;
    }

    /**
     * Resolve the KeyStoreType Object.
     *
     * @return The resolved KeyStoreType object
     * @throws ObjectStreamException if the KeyStoreType could not be resolved
     */
    private Object readResolve()
        throws ObjectStreamException
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
