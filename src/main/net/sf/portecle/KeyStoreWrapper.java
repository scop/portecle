/*
 * KeyStoreWrapper.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2006 Ville Skyttä, ville.skytta@iki.fi
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

package net.sf.portecle;

import java.io.File;
import java.security.KeyStore;
import java.util.HashMap;

import net.sf.portecle.crypto.KeyStoreType;

/**
 * Wrapper class for a keystore. Used to keep a track of the keystore's physical file, its password, the password's of
 * its protected entries and whether or not the keystore has been changed since it was last saved.
 */
class KeyStoreWrapper
{
	/** The wrapped keystore */
	private KeyStore m_keyStore;

	/** Type of the wrapped keystore */
	private KeyStoreType m_keyStoreType;

	/** The keystore's password */
	private char[] m_cPassword;

	/** Keystore entry passwords */
	private final HashMap<String, char[]> m_mPasswords = new HashMap<>();

	/** File the keystore was loaded from/saved to */
	private File m_fKeyStore;

	/**
	 * Indicator as to whether or not the keystore has been altered since its last save
	 */
	private boolean m_bChanged;

	/**
	 * Construct a new KeyStoreWrapper for the supplied keystore.
	 * 
	 * @param keyStore The keystore
	 */
	public KeyStoreWrapper(KeyStore keyStore)
	{
		setKeyStore(keyStore);
	}

	/**
	 * Construct a new KeyStoreWrapper for the supplied keystore, keystore file and keystore password.
	 * 
	 * @param keyStore The keystore
	 * @param fKeyStore The keystore file
	 * @param cPassword The keystore password
	 */
	public KeyStoreWrapper(KeyStore keyStore, File fKeyStore, char[] cPassword)
	{
		this(keyStore);
		m_fKeyStore = fKeyStore;
		m_cPassword = cPassword;
	}

	/**
	 * Set the password for a particular keystore entry in the wrapper.
	 * 
	 * @param sAlias The keystore entry's alias
	 * @param cPassword The keystore entry's password
	 */
	public void setEntryPassword(String sAlias, char[] cPassword)
	{
		m_mPasswords.put(sAlias, cPassword);
	}

	/**
	 * Remove a particular keystore entry from the wrapper.
	 * 
	 * @param sAlias The keystore entry's alias
	 */
	public void removeEntryPassword(String sAlias)
	{
		m_mPasswords.remove(sAlias);
	}

	/**
	 * Get the password for a particular keystore entry.
	 * 
	 * @param sAlias The keystore entry's alias
	 * @return The keystore entry's password or null if none is set
	 */
	public char[] getEntryPassword(String sAlias)
	{
		return m_mPasswords.get(sAlias);
	}

	/**
	 * Get the keystore's physical file.
	 * 
	 * @return The keystore entry's physical file or null if none is set
	 */
	public File getKeyStoreFile()
	{
		return m_fKeyStore;
	}

	/**
	 * Set the keystore's physical file in the wrapper.
	 * 
	 * @param fKeyStore The keystore entry's physical file
	 */
	public void setKeyStoreFile(File fKeyStore)
	{
		m_fKeyStore = fKeyStore;
	}

	/**
	 * Get the keystore.
	 * 
	 * @return The keystore
	 */
	public KeyStore getKeyStore()
	{
		return m_keyStore;
	}

	/**
	 * Set the keystore.
	 * 
	 * @param keyStore The keystore
	 */
	public void setKeyStore(KeyStore keyStore)
	{
		m_keyStore = keyStore;
		m_keyStoreType = KeyStoreType.valueOfType(keyStore.getType());
	}

	/**
	 * Get type of wrapped keystore.
	 * 
	 * @return type of wrapped keystore
	 */
	public KeyStoreType getKeyStoreType()
	{
		return m_keyStoreType;
	}

	/**
	 * Get the keystore password
	 * 
	 * @return The keystore password
	 */
	public char[] getPassword()
	{
		return m_cPassword;
	}

	/**
	 * Set the keystore password in the wrapper.
	 * 
	 * @param cPassword The keystore password
	 */
	public void setPassword(char[] cPassword)
	{
		m_cPassword = cPassword;
	}

	/**
	 * Register with the wrapper whether the keystore has been changed since its last save.
	 * 
	 * @param bChanged Has the keystore been changed?
	 */
	public void setChanged(boolean bChanged)
	{
		m_bChanged = bChanged;
	}

	/**
	 * Has the keystore been changed since its last save?
	 * 
	 * @return True if it has been changed, false otherwise
	 */
	public boolean isChanged()
	{
		return m_bChanged;
	}
}
