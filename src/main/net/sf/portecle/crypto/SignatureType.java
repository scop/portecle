/*
 * SignatureType.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004-2005 Ville Skyttä, ville.skytta@iki.fi
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

import java.io.InvalidObjectException;
import java.io.ObjectStreamException;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.ResourceBundle;

/**
 * Type safe enumeration of Signature Types supported by the X509CertUtil class.
 */
public class SignatureType
{
	/** MD2 with RSA Signature Type */
	public static final SignatureType RSA_MD2 = new SignatureType("MD2withRSA");

	/** MD5 with RSA Signature Type */
	public static final SignatureType RSA_MD5 = new SignatureType("MD5withRSA");

	/** SHA-1 with RSA Signature Type */
	public static final SignatureType RSA_SHA1 = new SignatureType("SHA1withRSA");

	/** SHA-224 with RSA Signature Type */
	public static final SignatureType RSA_SHA224 = new SignatureType("SHA224withRSA");

	/** SHA-256 with RSA Signature Type */
	public static final SignatureType RSA_SHA256 = new SignatureType("SHA256withRSA");

	/** SHA-384 with RSA Signature Type */
	public static final SignatureType RSA_SHA384 = new SignatureType("SHA384withRSA");

	/** SHA-512 with RSA Signature Type */
	public static final SignatureType RSA_SHA512 = new SignatureType("SHA512withRSA");

	/** RIPEMD128 with RSA Signature Type */
	public static final SignatureType RSA_RIPEMD128 = new SignatureType("RIPEMD128withRSA");

	/** RIPEMD160 with RSA Signature Type */
	public static final SignatureType RSA_RIPEMD160 = new SignatureType("RIPEMD160withRSA");

	/** RIPEMD256 with RSA Signature Type */
	public static final SignatureType RSA_RIPEMD256 = new SignatureType("RIPEMD256withRSA");

	/** SHA-1 with DSA Signature Type */
	public static final SignatureType DSA_SHA1 = new SignatureType("SHA1withDSA");

	/** SHA-1 with ECDSA Signature Type */
	public static final SignatureType ECDSA_SHA1 = new SignatureType("SHA1withECDSA");

	/** String-to-type map */
	private static final HashMap TYPE_MAP = new HashMap();
	static
	{
		TYPE_MAP.put(RSA_MD2.toString(), RSA_MD2);
		TYPE_MAP.put(RSA_MD5.toString(), RSA_MD5);
		TYPE_MAP.put(RSA_SHA1.toString(), RSA_SHA1);
		TYPE_MAP.put(RSA_SHA224.toString(), RSA_SHA224);
		TYPE_MAP.put(RSA_SHA256.toString(), RSA_SHA256);
		TYPE_MAP.put(RSA_SHA384.toString(), RSA_SHA384);
		TYPE_MAP.put(RSA_SHA512.toString(), RSA_SHA512);
		TYPE_MAP.put(RSA_RIPEMD128.toString(), RSA_RIPEMD128);
		TYPE_MAP.put(RSA_RIPEMD160.toString(), RSA_RIPEMD160);
		TYPE_MAP.put(RSA_RIPEMD256.toString(), RSA_RIPEMD256);
		TYPE_MAP.put(DSA_SHA1.toString(), DSA_SHA1);
		TYPE_MAP.put(ECDSA_SHA1.toString(), ECDSA_SHA1);
	}

	/** OID-to-type map */
	private static final HashMap OID_MAP = new HashMap();
	static
	{
		OID_MAP.put("1.2.840.113549.1.1.2", RSA_MD2);
		OID_MAP.put("1.2.840.113549.1.1.4", RSA_MD5);
		OID_MAP.put("1.2.840.113549.1.1.5", RSA_SHA1);
		OID_MAP.put("1.2.840.113549.1.1.14", RSA_SHA224);
		OID_MAP.put("1.2.840.113549.1.1.11", RSA_SHA256);
		OID_MAP.put("1.2.840.113549.1.1.12", RSA_SHA384);
		OID_MAP.put("1.2.840.113549.1.1.13", RSA_SHA512);
		OID_MAP.put("1.3.36.3.3.1.3", RSA_RIPEMD128);
		OID_MAP.put("1.3.36.3.3.1.2", RSA_RIPEMD160);
		OID_MAP.put("1.3.36.3.3.1.4", RSA_RIPEMD256);
		OID_MAP.put("1.2.840.10040.4.3", DSA_SHA1);
		OID_MAP.put("1.2.840.10045.4.1", ECDSA_SHA1);
	}

	/** Resource bundle */
	private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/crypto/resources");

	/** Stores Signature Type name */
	private final String m_sType;

	/**
	 * Construct a SignatureType. Private to prevent construction from outside this class.
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
		if (st == null)
		{
			throw new CryptoException(MessageFormat.format(
			    m_res.getString("NoResolveSignaturetype.exception.message"), new String[] { sType }));
		}
		return st;
	}

	/**
	 * Gets a SignatureType corresponding to the given OID.
	 * 
	 * @param oid the object identifier
	 * @return the corresponding SignatureType
	 */
	public static SignatureType forOid(String oid)
	{
		SignatureType st = (SignatureType) OID_MAP.get(oid);
		return st == null ? new SignatureType(oid) : st;
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
		try
		{
			return getInstance(m_sType);
		}
		catch (CryptoException e)
		{
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
