/*
 * KeyStoreUtil.java
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
import java.util.ResourceBundle;
import java.text.MessageFormat;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * Provides utility methods for loading/saving KeyStores.  The BouncyCastle provider
 * must be added before using this class to create or load a PKCS12, BKS or UBER type
 * KeyStores.
 */
public final class KeyStoreUtil extends Object
{
    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/crypto/resources");

    /**
     * Private to prevent construction.
     */
    private KeyStoreUtil() {}

    /**
     * Create a new, empty KeyStore.
     *
     * @param keyStoreType The KeyStore type to create
     * @return The KeyStore
     * @throws CryptoException Problem encountered creating the KeyStore
     * @throws IOException An I/O error occurred
     */
    public static KeyStore createKeyStore(KeyStoreType keyStoreType) throws CryptoException, IOException
    {
        KeyStore keyStore = null;

        // Create a new keystore by using load with null parameters
        try
        {
            if ((keyStoreType == KeyStoreType.PKCS12) || (keyStoreType == KeyStoreType.BKS) ||
                (keyStoreType == KeyStoreType.UBER))
            {
                // Need BC provider for PKCS #12, BKS and UBER
                if (Security.getProvider("BC") == null)
                {
                    throw new CryptoException(m_res.getString("NoBcProvider.exception.message"));
                }
                keyStore = KeyStore.getInstance(keyStoreType.toString(), "BC");
            }
            else
            {
                keyStore = KeyStore.getInstance(keyStoreType.toString());
            }
            keyStore.load(null, null);
        }
        catch (KeyStoreException ex)
        {
            throw new CryptoException(m_res.getString("NoCreateKeystore.exception.message"), ex);
        }
        catch (CertificateException ex)
        {
            throw new CryptoException(m_res.getString("NoCreateKeystore.exception.message"), ex);
        }
        catch (NoSuchProviderException ex)
        {
            throw new CryptoException(m_res.getString("NoCreateKeystore.exception.message"), ex);
        }
        catch (NoSuchAlgorithmException ex)
        {
            throw new CryptoException(m_res.getString("NoCreateKeystore.exception.message"), ex);
        }

        // Return the keystore
        return keyStore;
    }

    /**
     * Load a Keystore from a file accessed by a password.
     *
     * @param keyStoreType The type of the KeyStore to open
     * @param fKeyStore File to load KeyStore from
     * @param cPassword Password of the KeyStore
     * @return The KeyStore
     * @throws CryptoException Problem encountered loading the KeyStore
     * @throws FileNotFoundException If the KeyStore file does not exist,
     *                               is a directory rather than a regular
     *                               file, or for some other reason cannot
     *                               be opened for reading
     */
    public static KeyStore loadKeyStore(File fKeyStore, char[] cPassword, KeyStoreType keyStoreType)
        throws CryptoException, FileNotFoundException
    {
        // Open an input stream on the keystore file
        FileInputStream fis = new FileInputStream(fKeyStore);

        // Create a keystore object
        KeyStore keyStore = null;
        try
        {
            if ((keyStoreType == KeyStoreType.PKCS12) || (keyStoreType == KeyStoreType.BKS) ||
                (keyStoreType == KeyStoreType.UBER))
            {
                // Need BC provider for PKCS #12, BKS and UBER
                if (Security.getProvider("BC") == null)
                {
                    throw new CryptoException(m_res.getString("NoBcProvider.exception.message"));
                }

                keyStore = KeyStore.getInstance(keyStoreType.toString(), "BC");
            }
            else
            {
                keyStore = KeyStore.getInstance(keyStoreType.toString());
            }
        }
        catch (KeyStoreException ex)
        {
            throw new CryptoException(m_res.getString("NoCreateKeystore.exception.message"), ex);
        }
        catch (NoSuchProviderException ex)
        {
            throw new CryptoException(m_res.getString("NoCreateKeystore.exception.message"), ex);
        }

        try
        {
            // Load the file into the keystore
            keyStore.load(fis, cPassword);
        }
        catch (CertificateException ex)
        {
            throw new CryptoException(MessageFormat.format(m_res.getString("NoLoadKeystore.exception.message"), new Object[]{keyStoreType}), ex);
        }
        catch (NoSuchAlgorithmException ex)
        {
            throw new CryptoException(MessageFormat.format(m_res.getString("NoLoadKeystore.exception.message"), new Object[]{keyStoreType}), ex);
        }
        catch (FileNotFoundException ex)
        {
            throw ex;
        }
        catch (IOException ex)
        {
            throw new CryptoException(MessageFormat.format(m_res.getString("NoLoadKeystore.exception.message"), new Object[]{keyStoreType}), ex);
        }

        // Close the stream
        try { fis.close(); } catch (IOException ex) { /* Ignore */ }

        // Return the keystore
        return keyStore;
    }

    /**
     * Save a KeyStore to a file protected by a password.
     *
     * @param keyStore The KeyStore
     * @param fKeyStoreFile The file to save the KeyStore to
     * @param cPassword The password to protect the KeyStore with
     * @throws CryptoException Problem encountered saving the KeyStore
     * @throws FileNotFoundException If the KeyStore file exists but is a
     *                               directory rather than a regular file,
     *                               does not exist but cannot be created,
     *                               or cannot be opened for any other reason
     * @throws IOException An I/O error occurred
     */
    public static void saveKeyStore(KeyStore keyStore, File fKeyStoreFile, char[] cPassword)
        throws CryptoException, IOException
    {
        FileOutputStream fos = null;

        // Setup an output stream for the admin keystore
        fos = new FileOutputStream(fKeyStoreFile);

        try
        {
            // Store the keystore to file with password protection
            keyStore.store(fos, cPassword);
        }
        catch (IOException ex)
        {
            throw new CryptoException(m_res.getString("NoSaveKeystore.exception.message"), ex);
        }
        catch (KeyStoreException ex)
        {
            throw new CryptoException(m_res.getString("NoSaveKeystore.exception.message"), ex);
        }
        catch (CertificateException ex)
        {
            throw new CryptoException(m_res.getString("NoSaveKeystore.exception.message"), ex);
        }
        catch (NoSuchAlgorithmException ex)
        {
            throw new CryptoException(m_res.getString("NoSaveKeystore.exception.message"), ex);
        }

        // Close the stream
        fos.close();
    }
}
