/*
 * SignatureType.java
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
import java.util.HashMap;
import java.util.ResourceBundle;

/**
 * Type safe enumeration of Signature Types supported by the
 * X509CertUtil class.
 */
public class SignatureType extends Object
{
    /** MD2 with RSA Sigature Type */
    public static final SignatureType RSA_MD2 =
        new SignatureType("MD2withRSA");

    /** MD5 with RSA Sigature Type */
    public static final SignatureType RSA_MD5 =
        new SignatureType("MD5withRSA");

    /** SHA.1 with RSA Sigature Type */
    public static final SignatureType RSA_SHA1 =
        new SignatureType("SHA1withRSA");

    /** SHA.1 with DSA Sigature Type */
    public static final SignatureType DSA_SHA1 =
        new SignatureType("SHA1withDSA");

    /** String-to-type map */
    private static final HashMap TYPE_MAP = new HashMap();
    static {
        TYPE_MAP.put(RSA_MD2.toString(),  RSA_MD2);
        TYPE_MAP.put(RSA_MD5.toString(),  RSA_MD5);
        TYPE_MAP.put(RSA_SHA1.toString(), RSA_SHA1);
        TYPE_MAP.put(DSA_SHA1.toString(), DSA_SHA1);
    }

    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/crypto/resources");

    /** Stores Signature Type name */
    private final String m_sType;

    /**
     * Construct a SignatureType.  Private to prevent construction
     * from outside this class.
     *
     * @param sType Signature type
     */
    private SignatureType(String sType)
    {
        m_sType = sType;
    }

    /**
     * Gets a SignatureType corresponding to the given type String.
     *
     * @param sType the signature type name
     * @return the corresponding SignatureType
     * @throws CryptoException if the type is not known
     */
    public static SignatureType getInstance(String sType)
        throws CryptoException
    {
        SignatureType st = (SignatureType) TYPE_MAP.get(sType);
        if (st == null) {
            throw new CryptoException(
                MessageFormat.format(
                    m_res.getString(
                        "NoResolveSignaturetype.exception.message"),
                    new String[]{sType}));
        }
        return st;
    }

    /**
     * Resolve the SignatureType Object.
     *
     * @return The resolved SignatureType object
     * @throws ObjectStreamException if the SignatureType could not be resolved
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
     * Return string representation of Signature Type compatible with the JCE.
     *
     * @return String representation of a Signature Type
     */
    public String toString()
    {
        return m_sType;
    }
}
