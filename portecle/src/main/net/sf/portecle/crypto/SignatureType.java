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
import java.util.ResourceBundle;

/**
 * Type safe enumeration of Signature Types supported by the
 * X509CertUtil class.
 */
public class SignatureType extends Object
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/crypto/resources");

    /** Stores Signature Type name */
    private final String m_sType;

    /** MD2 with RSA Sigature Type JCE String */
    private static final String RSA_MD2_STR = "MD2withRSA";

    /** MD5 with RSA Sigature Type JCE String */
    private static final String RSA_MD5_STR = "MD5withRSA";

    /** SHA.1 with RSA Sigature Type JCE String */
    private static final String RSA_SHA1_STR = "SHA1withRSA";

    /** SHA.1 with DSA Sigature Type JCE String */
    private static final String DSA_SHA1_STR = "SHA1withDSA";

    /** MD2 with RSA Sigature Type */
    public static final SignatureType RSA_MD2 = new SignatureType(RSA_MD2_STR);

    /** MD5 with RSA Sigature Type */
    public static final SignatureType RSA_MD5 = new SignatureType(RSA_MD5_STR);

    /** SHA.1 with RSA Sigature Type */
    public static final SignatureType RSA_SHA1 =
        new SignatureType(RSA_SHA1_STR);

    /** SHA.1 with DSA Sigature Type */
    public static final SignatureType DSA_SHA1 =
        new SignatureType(DSA_SHA1_STR);

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
     * Resolve the SignatureType Object.
     *
     * @return The resolved SignatureType object
     * @throws ObjectStreamException if the SignatureType could not be resolved
     */
    private Object readResolve () throws ObjectStreamException
    {
        if (m_sType.equals(RSA_MD2_STR))
        {
            return RSA_MD2;
        }
        else if (m_sType.equals(RSA_MD5_STR))
        {
            return RSA_MD5;
        }
        else if (m_sType.equals(RSA_SHA1_STR))
        {
            return RSA_SHA1;
        }
        else if (m_sType.equals(DSA_SHA1_STR))
        {
            return DSA_SHA1;
        }
        else
        {
            throw new InvalidObjectException(
                MessageFormat.format(
                    "NoResolveSignaturetype.exception.message",
                    new Object[]{m_sType}));
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
