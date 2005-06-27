/*
 * KeyPairUtil.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2005 Ville Skyttä, ville.skytta@iki.fi
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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.ResourceBundle;

/**
 * Provides utility methods for the generation of keys.
 */
public final class KeyPairUtil
{
    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/crypto/resources");

    /**
     * Private to prevent construction.
     */
    private KeyPairUtil() {}

    /**
     * Generate a key pair.
     *
     * @param keyPairType Key pair type to generate
     * @param iKeySize Key size of key pair
     * @return A key pair
     * @throws CryptoException If there was a problem generating the key pair
     */
    public static KeyPair generateKeyPair(KeyPairType keyPairType,
                                          int iKeySize)
        throws CryptoException
    {
        try
        {
            // We could request BC here in order to gain support for generating
            // > 2048 bit RSA keys also on Java 1.4.  But unless there's a way
            // to eg. read JKS keystores containing such keys on Java 1.4,
            // that would just help the user shoot herself in the foot...
            KeyPairGenerator keyPairGen =
                KeyPairGenerator.getInstance(keyPairType.toString());

            // Create a SecureRandom
            SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");

            // Initialise key pair generator with key strength and a randomness
            keyPairGen.initialize(iKeySize, rand);

            // Generate and return the key pair
            KeyPair keyPair = keyPairGen.generateKeyPair();
            return keyPair;
        }
        catch (NoSuchAlgorithmException ex)
        {
            throw new CryptoException(
                MessageFormat.format(
                    m_res.getString("NoGenerateKeypair.exception.message"),
                    new Object[]{keyPairType}), ex);
        }
        catch (InvalidParameterException ex)
        {
            throw new CryptoException(
                MessageFormat.format(
                    m_res.getString("NoGenerateKeypairParm.exception.message"),
                    new Object[]{keyPairType}), ex);
        }
    }
}
