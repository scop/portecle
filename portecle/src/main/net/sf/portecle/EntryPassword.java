/*
 * EntryPassword.java
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

package net.sf.portecle;

/**
 * Holds an alias/password pair for a KeyStore entry.
 */
class EntryPassword
{
    /** KeyStore entry alias */
    private String m_sAlias;

    /** KeyStore entry password */
    private char[] m_cPassword;

    /**
     * Creates a new KeyStoreEntry with the specified alias.
     *
     * @param sAlias The alias
     */
    public EntryPassword(String sAlias)
    {
        m_sAlias = sAlias;
    }

    /**
     * Creates a new KeyStoreEntry with the specified alias and password.
     *
     * @param sAlias The alias
     * @param cPassword The password
     */
    public EntryPassword(String sAlias, char[] cPassword)
    {
        m_sAlias = sAlias;
        m_cPassword = cPassword;
    }

    /**
     * Get the entry alias.
     *
     * @return The entry alias
     */
    public String getAlias()
    {
        return m_sAlias;
    }

    /**
     * Get the entry password.
     *
     * @return The entry password
     */
    public char[] getPassword()
    {
        return m_cPassword;
    }

    /**
     * Set the entry password.
     *
     * @param cPassword The password
     */
    public void setPassword(char[] cPassword)
    {
        m_cPassword = cPassword;
    }
}
