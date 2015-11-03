/*
 * KeyStoreUtil.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004-2014 Ville Skyttä, ville.skytta@iki.fi
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

import static net.sf.portecle.FPortecle.RB;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

/**
 * Provides utility methods for loading/saving keystores. The Bouncy Castle provider must be registered before using
 * this class to create or load BKS or UBER type keystores.
 */
public final class KeyStoreUtil
{
	/**
	 * Dummy password to use for keystore entries in various contexts of keystores that do not support entry passwords.
	 */
	public static final char[] DUMMY_PASSWORD = "password".toCharArray();

	/** Map of available keystore types */
	private static final HashMap<KeyStoreType, Boolean> AVAILABLE_TYPES = new HashMap<>();

	/**
	 * Private to prevent construction.
	 */
	private KeyStoreUtil()
	{
		// Nothing to do
	}

	/**
	 * Gets the preferred (by us) KeyStore instance for the given keystore type.
	 * 
	 * @param keyStoreType The keystore type
	 * @return The keystore
	 * @throws KeyStoreException No implementation found
	 */
	private static KeyStore getKeyStoreImpl(KeyStoreType keyStoreType)
	    throws KeyStoreException
	{
		KeyStore keyStore = null;
		if (keyStoreType == KeyStoreType.PKCS12)
		{
			// Prefer BC for PKCS #12 for now; the BC and SunJSSE 1.5+ implementations are incompatible in how
			// they handle empty/missing passwords; BC works consistently with char[0] on load and store (does
			// not accept nulls), SunJSSE throws division by zero with char[0] on load and store, works with
			// null on load, does not work with null on store.
			// Checked with BC 1.{29,40}, SunJSSE 1.5.0_0{3,4,14}, 1.6.0 (OpenJDK)
			try
			{
				keyStore = KeyStore.getInstance(keyStoreType.getTypeName(), "BC");
			}
			catch (NoSuchProviderException ex)
			{
				// Fall through
			}
		}
		if (keyStore == null)
		{
			try
			{
				keyStore = KeyStore.getInstance(keyStoreType.getTypeName());
			}
			catch (KeyStoreException e)
			{
				AVAILABLE_TYPES.put(keyStoreType, Boolean.FALSE);
				throw e;
			}
		}
		AVAILABLE_TYPES.put(keyStoreType, Boolean.TRUE);
		return keyStore;
	}

	/**
	 * Create a new, empty keystore.
	 * 
	 * @param keyStoreType The keystore type to create
	 * @return The keystore
	 * @throws CryptoException Problem encountered creating the keystore
	 * @throws IOException An I/O error occurred
	 */
	public static KeyStore createKeyStore(KeyStoreType keyStoreType)
	    throws CryptoException, IOException
	{
		KeyStore keyStore = null;
		try
		{
			keyStore = getKeyStoreImpl(keyStoreType);
			keyStore.load(null, null);
		}
		catch (GeneralSecurityException ex)
		{
			throw new CryptoException(
			    MessageFormat.format(RB.getString("NoCreateKeystore.exception.message"), keyStoreType), ex);
		}
		return keyStore;
	}

	/**
	 * Load keystore entries from PEM reader into a new PKCS #12 keystore. The reader is not closed.
	 * 
	 * @param reader reader to read entries from
	 * @param pwFinder object to get passwords from on demand
	 * @return new PKCS #12 keystore containing read entries, possibly empty
	 * @throws CryptoException Problem encountered creating the keystore
	 * @throws IOException An I/O error occurred
	 */
	public static KeyStore loadEntries(PEMParser reader, PasswordFinder pwFinder)
	    throws CertificateException, CryptoException, IOException
	{
		LinkedHashSet<KeyPair> keyPairs = new LinkedHashSet<>();
		LinkedHashSet<Certificate> certs = new LinkedHashSet<>();
		KeyStore keyStore = createKeyStore(KeyStoreType.PKCS12);

		CertificateFactory cf = CertificateFactory.getInstance(X509CertUtil.X509_CERT_TYPE);
		JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter();

		Object obj;
		while ((obj = reader.readObject()) != null)
		{
			if (obj instanceof PEMEncryptedKeyPair)
			{
				PEMDecryptorProvider decryptor = new JcePEMDecryptorProviderBuilder().build(pwFinder.getPassword());
				obj = ((PEMEncryptedKeyPair) obj).decryptKeyPair(decryptor);
			}
			if (obj instanceof PEMKeyPair)
			{
				keyPairs.add(keyConverter.getKeyPair((PEMKeyPair) obj));
			}
			else if (obj instanceof X509CertificateHolder)
			{
				ByteArrayInputStream bais = new ByteArrayInputStream(((X509CertificateHolder) obj).getEncoded());
				certs.add(cf.generateCertificate(bais));
			}
		}

		// Add key pairs
		for (KeyPair keyPair : keyPairs)
		{
			Certificate keyPairCert = null;
			for (Iterator<Certificate> it = certs.iterator(); it.hasNext();)
			{
				Certificate cert = it.next();
				if (cert.getPublicKey().equals(keyPair.getPublic()))
				{
					keyPairCert = cert;
					it.remove();
					break;
				}
			}

			if (keyPairCert != null)
			{
				String alias = "keypair";
				if (keyPairCert instanceof X509Certificate)
				{
					alias = X509CertUtil.getCertificateAlias((X509Certificate) keyPairCert);
				}

				KeyStore.PrivateKeyEntry entry =
				    new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), new Certificate[] { keyPairCert });
				KeyStore.PasswordProtection prot = new KeyStore.PasswordProtection(DUMMY_PASSWORD);

				try
				{
					alias = findUnusedAlias(keyStore, alias);
					keyStore.setEntry(alias, entry, prot);
				}
				catch (KeyStoreException e)
				{
					throw new CryptoException(e);
				}
			}
		}

		// Add remaining certificates as trusted certificate entries
		for (Certificate cert : certs)
		{
			String alias = "certificate";
			if (cert instanceof X509Certificate)
			{
				alias = X509CertUtil.getCertificateAlias((X509Certificate) cert);
			}

			KeyStore.TrustedCertificateEntry entry = new KeyStore.TrustedCertificateEntry(cert);
			try
			{
				keyStore.setEntry(alias, entry, null);
			}
			catch (KeyStoreException e)
			{
				throw new CryptoException(e);
			}
		}

		return keyStore;
	}

	/**
	 * Check if a keystore type is available.
	 * 
	 * @param keyStoreType the keystore type
	 * @return true if the keystore type is available, false otherwise
	 */
	public static boolean isAvailable(KeyStoreType keyStoreType)
	{
		Boolean available;
		if ((available = AVAILABLE_TYPES.get(keyStoreType)) != null)
		{
			return available;
		}
		try
		{
			// Populate AVAILABLE_TYPES
			getKeyStoreImpl(keyStoreType);
		}
		catch (KeyStoreException e)
		{
			// Ignore
		}
		return AVAILABLE_TYPES.get(keyStoreType);
	}

	/**
	 * Get available keystore types.
	 * 
	 * @return available keystore types
	 */
	public static KeyStoreType[] getAvailableTypes()
	{
		// TODO: populate only once
		KeyStoreType[] known = KeyStoreType.values();
		ArrayList<KeyStoreType> available = new ArrayList<>();
		for (KeyStoreType type : known)
		{
			if (isAvailable(type))
			{
				available.add(type);
			}
		}
		return available.toArray(new KeyStoreType[available.size()]);
	}

	/**
	 * Load a Keystore from a file accessed by a password.
	 * 
	 * @param keyStoreType The type of the keystore to open
	 * @param fKeyStore File to load keystore from
	 * @param cPassword Password of the keystore
	 * @return The keystore
	 * @throws CryptoException Problem encountered loading the keystore
	 * @throws FileNotFoundException If the keystore file does not exist, is a directory rather than a regular file, or
	 *             for some other reason cannot be opened for reading
	 */
	public static KeyStore loadKeyStore(File fKeyStore, char[] cPassword, KeyStoreType keyStoreType)
	    throws CryptoException, FileNotFoundException
	{
		KeyStore keyStore = null;
		try
		{
			keyStore = getKeyStoreImpl(keyStoreType);
		}
		catch (KeyStoreException ex)
		{
			throw new CryptoException(
			    MessageFormat.format(RB.getString("NoCreateKeystore.exception.message"), keyStoreType), ex);
		}

		try (FileInputStream fis = new FileInputStream(fKeyStore))
		{
			keyStore.load(fis, cPassword);
		}
		catch (FileNotFoundException ex)
		{
			throw ex;
		}
		catch (GeneralSecurityException | IOException ex)
		{
			throw new CryptoException(
			    MessageFormat.format(RB.getString("NoLoadKeystore.exception.message"), keyStoreType), ex);
		}

		return keyStore;
	}

	/**
	 * Load a PKCS #11 keystore accessed by a password.
	 * 
	 * @param sPkcs11Provider The name of the PKCS #11 provider
	 * @param cPassword Password of the keystore
	 * @return The keystore
	 * @throws CryptoException Problem encountered loading the keystore
	 */
	public static KeyStore loadKeyStore(String sPkcs11Provider, char[] cPassword)
	    throws CryptoException
	{
		KeyStore keyStore = null;

		try
		{
			if (Security.getProvider(sPkcs11Provider) == null)
			{
				throw new CryptoException(
				    MessageFormat.format(RB.getString("NoSuchProvider.exception.message"), sPkcs11Provider));
			}
			keyStore = KeyStore.getInstance(KeyStoreType.PKCS11.name(), sPkcs11Provider);
		}
		catch (GeneralSecurityException ex)
		{
			throw new CryptoException(
			    MessageFormat.format(RB.getString("NoCreateKeystore.exception.message"), KeyStoreType.PKCS11), ex);
		}

		try
		{
			keyStore.load(null, cPassword);
		}
		catch (Exception ex)
		{
			throw new CryptoException(
			    MessageFormat.format(RB.getString("NoLoadKeystore.exception.message"), KeyStoreType.PKCS11), ex);
		}

		return keyStore;
	}

	/**
	 * Save a keystore to a file protected by a password.
	 * 
	 * @param keyStore The keystore
	 * @param fKeyStoreFile The file to save the keystore to
	 * @param cPassword The password to protect the keystore with
	 * @return the saved keystore ready for further use
	 * @throws CryptoException Problem encountered saving the keystore
	 * @throws FileNotFoundException If the keystore file exists but is a directory rather than a regular file, does not
	 *             exist but cannot be created, or cannot be opened for any other reason
	 * @throws IOException An I/O error occurred
	 */
	public static KeyStore saveKeyStore(KeyStore keyStore, File fKeyStoreFile, char[] cPassword)
	    throws CryptoException, IOException
	{
		try (FileOutputStream fos = new FileOutputStream(fKeyStoreFile))
		{
			keyStore.store(fos, cPassword);
		}
		catch (GeneralSecurityException | IOException ex)
		{
			throw new CryptoException(RB.getString("NoSaveKeystore.exception.message"), ex);
		}

		// As of GNU classpath 0.92, we need to reload GKR keystores after storing them, otherwise
		// "masked envelope" IllegalStateExceptions occur when trying to access things in the stored keystore
		// again.
		if (KeyStoreType.valueOfType(keyStore.getType()) == KeyStoreType.GKR)
		{
			keyStore = loadKeyStore(fKeyStoreFile, cPassword, KeyStoreType.GKR);
		}

		return keyStore;
	}

	/**
	 * Find an unused alias in the keystore based on the given alias.
	 * 
	 * @param keyStore the keystore
	 * @param alias the alias
	 * @return alias that is not in use in the keystore
	 * @throws KeyStoreException
	 */
	private static String findUnusedAlias(KeyStore keyStore, String alias)
	    throws KeyStoreException
	{
		if (keyStore.containsAlias(alias))
		{
			int i = 1;
			while (true)
			{
				String nextAlias = alias + " (" + i + ")";
				if (!keyStore.containsAlias(nextAlias))
				{
					alias = nextAlias;
					break;
				}
			}
		}
		return alias;
	}
}
