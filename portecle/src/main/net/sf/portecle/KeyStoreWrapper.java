/*
 * KeyStoreWrapper.java
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

package net.sf.portecle;

import java.util.*;
import java.security.*;
import java.io.*;

/**
 * Wrapper class for a KeyStore.  Used to keep a track of the KeyStore's
 * physical file, its password, the password's of its protected entries
 * and whether or not the KeyStore has been changed since it was last saved.
 */
class KeyStoreWrapper extends Object
{
    /** The wrapped KeyStore */
    private KeyStore m_keyStore;

    /** The KeyStore's password */
    private char[] m_cPassword;

    /** KeyStore entry passwords as a Vector of EntryPassword objects */
    private Vector m_vEntryPasswords;

    /** File the KeyStore was loaded from/saved to */
    private File m_fKeyStore;

    /** Indicator as to whether or not the KeyStore has been altered since its last save */
    private boolean m_bChanged = false;

    /**
     * Construst a new KeyStoreWrapper for the supplied KeyStore.
     *
     * @param keyStore The KeyStore
     */
    public KeyStoreWrapper(KeyStore keyStore)
    {
        m_keyStore = keyStore;
        m_vEntryPasswords = new Vector();
    }

    /**
     * Construst a new KeyStoreWrapper for the supplied KeyStore, KeyStore file
     * and KeyStore password.
     *
     * @param keyStore The KeyStore
     * @param fKeyStore The KeyStore file
     * @param cPassword The KeyStore password
     */
    public KeyStoreWrapper(KeyStore keyStore, File fKeyStore, char[] cPassword)
    {
        this(keyStore);
        m_fKeyStore = fKeyStore;
        m_cPassword = cPassword;
    }

    /**
     * Set the password for a particular KeyStore entry in the wrapper.
     *
     * @param sAlias The KeyStore entry's alias
     * @param cPassword The KeyStore entry's password
     */
    public void setEntryPassword(String sAlias, char[] cPassword)
    {
        for (int iCnt=0; iCnt < m_vEntryPasswords.size(); iCnt++)
        {
            EntryPassword entry = (EntryPassword)m_vEntryPasswords.get(iCnt);
            if (sAlias.equalsIgnoreCase(entry.getAlias()))
            {
                entry.setPassword(cPassword);
                return;
            }
        }
        m_vEntryPasswords.add(new EntryPassword(sAlias, cPassword));
    }

    /**
     * Remove a particular KeyStore entry from the wrapper.
     *
     * @param sAlias The KeyStore entry's alias
     */
    public void removeEntryPassword(String sAlias)
    {
        for (int iCnt=0; iCnt < m_vEntryPasswords.size(); iCnt++)
        {
            EntryPassword entry = (EntryPassword)m_vEntryPasswords.get(iCnt);
            if (sAlias.equalsIgnoreCase(entry.getAlias()))
            {
                m_vEntryPasswords.remove(iCnt);
                break;
            }
        }
    }

    /**
     * Get the password for a particular KeyStore entry.
     *
     * @param sAlias The KeyStore entry's alias
     * @return The KeyStore entry's password or null if none is set
     */
    public char[] getEntryPassword(String sAlias)
    {
        for (int iCnt=0; iCnt < m_vEntryPasswords.size(); iCnt++)
        {
            EntryPassword entry = (EntryPassword)m_vEntryPasswords.get(iCnt);
            if (sAlias.equalsIgnoreCase(entry.getAlias()))
            {
                return entry.getPassword();
            }
        }
        return null;
    }

    /**
     * Get the KeyStore's physical file.
     *
     * @return The KeyStore entry's physical file or null if none is set
     */
    public File getKeyStoreFile()
    {
        return m_fKeyStore;
    }

    /**
     * Set the KeyStore's physical file in the wrapper.
     *
     * @param fKeyStore The KeyStore entry's physical file
     */
    public void setKeyStoreFile(File fKeyStore)
    {
        m_fKeyStore = fKeyStore;
    }

    /**
     * Get the KeyStore.
     *
     * @return The KeyStore
     */
    public KeyStore getKeyStore()
    {
        return m_keyStore;
    }

    /**
     * Set the KeyStore.
     *
     * @param keyStore The KeyStore
     */
    public void setKeyStore(KeyStore keyStore)
    {
        m_keyStore = keyStore;
    }

    /**
     * Get the KeyStore password
     *
     * @return The KeyStore password
     */
    public char[] getPassword()
    {
        return m_cPassword;
    }

    /**
     * Set the KeyStore password in the wrapper.
     *
     * @param cPassword The KeyStore password
     */
    public void setPassword(char[] cPassword)
    {
        m_cPassword = cPassword;
    }

    /**
     * Register with the wrapper whether the KeyStore has been changed since
     * its last save.
     *
     * @param bChanged Has the KeyStore been changed?
     */
    public void setChanged(boolean bChanged)
    {
        m_bChanged = bChanged;
    }

    /**
     * Has the KeyStore been changed since its last save?
     *
     * @return True if it has been changed, false otherwise
     */
    public boolean isChanged()
    {
        return m_bChanged;
    }
}
