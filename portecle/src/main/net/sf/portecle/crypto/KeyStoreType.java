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

import java.io.InvalidObjectException;
import java.io.ObjectStreamException;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.ResourceBundle;

/**
 * Type safe enumeration of KeyStore Types supported by the KeyStoreUtil
 * class.
 */
public class KeyStoreType extends Object
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/crypto/resources");

    /** Stores KeyStore Type name */
    private final String m_sType;

    /** Whether the keystore type supports creation dates */
    private final boolean m_bCreationDate;

    /** JCEKS KeyStore Type JCE String */
    private static final String JCEKS_STR = "JCEKS";

    /** JKS KeyStore Type JCE String */
    private static final String JKS_STR = "JKS";

    /** PKCS #11 KeyStore Type JCE String */
    private static final String PKCS11_STR = "PKCS11";

    /** PKCS #12 KeyStore Type JCE String */
    private static final String PKCS12_STR = "PKCS12";

    /** BKS KeyStore Type JCE String */
    private static final String BKS_STR = "BKS";

    /** UBER KeyStore Type JCE String */
    private static final String UBER_STR = "UBER";

    /** JCEKS KeyStore Type */
    public static final KeyStoreType JCEKS =
        new KeyStoreType(JCEKS_STR, true);

    /** JKS KeyStore Type */
    public static final KeyStoreType JKS =
        new KeyStoreType(JKS_STR, true);

    /** PKCS #11 KeyStore Type */
    public static final KeyStoreType PKCS11 =
        new KeyStoreType(PKCS11_STR, false);

    /** PKCS #12 KeyStore Type */
    public static final KeyStoreType PKCS12 =
        new KeyStoreType(PKCS12_STR, false);

    /** BKS KeyStore Type */
    public static final KeyStoreType BKS =
        new KeyStoreType(BKS_STR, true);

    /** UBER KeyStore Type */
    public static final KeyStoreType UBER =
        new KeyStoreType(UBER_STR, true);

    private static final HashMap TYPE_MAP = new HashMap();
    static {
        TYPE_MAP.put(JKS_STR, JKS);
        TYPE_MAP.put(JCEKS_STR, JCEKS);
        TYPE_MAP.put(PKCS11_STR, PKCS11);
        TYPE_MAP.put(PKCS12_STR, PKCS12);
        TYPE_MAP.put(BKS_STR, BKS);
        TYPE_MAP.put(UBER_STR, UBER);
    }

    /**
     * Construct a KeyStoreType.
     * Private to prevent construction from outside this class.
     *
     * @param sType KeyStore type
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
     * Return string representation of KeyStore Type compatible with the JCE.
     *
     * @return String representation of a KeyStore Type
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
