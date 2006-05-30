/*
 * NameUtil.java
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

import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.X509Name;

/**
 * Provides utility methods relating to X50* names.
 */
public final class NameUtil
{
    /**
     * Private to prevent construction.
     */
    private NameUtil()
    {
    }

    /**
     * Gets the common name from the given X509Name.
     * 
     * @param name the X.509 name
     * @return the common name, null if not found
     */
    public static String getCommonName(X509Name name)
    {
        if (name == null)
            return null;
        Vector oids = name.getOIDs();
        int ix;
        if ((ix = oids.indexOf(X509Name.CN)) != -1) {
            Object val = name.getValues().get(ix);
            if (val != null)
                return val.toString();
        }
        return null;
    }

    /**
     * Gets the common name from the given X500Principal.
     * 
     * @param name the X.500 principal
     * @return the common name, null if not found
     */
    public static String getCommonName(X500Principal name)
    {
        if (name == null)
            return null;
        return getCommonName(new X509Name(name.getName()));
    }
}
