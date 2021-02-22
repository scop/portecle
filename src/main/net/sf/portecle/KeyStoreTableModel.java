/*
 * KeyStoreTableModel.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2008 Ville Skyttä, ville.skytta@iki.fi
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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;

import javax.swing.table.AbstractTableModel;

import net.sf.portecle.crypto.KeyStoreType;

/**
 * The table model used to display a keystore's entries sorted by alias name.
 */
class KeyStoreTableModel
    extends AbstractTableModel
{
	/** main view columns */
	public  static final int COLUMN_TYPE = 0;
	public  static final int COLUMN_EXPIRATION = 1;
	public  static final int COLUMN_ALIAS = 2;
	public  static final int COLUMN_DATESTART = 3;
	public  static final int COLUMN_DATEEND = 4;
	public  static final int COLUMN_DATELASTMODIFIED = 5;
	
	/** Column names */
	private static final String[] COLUMN_NAMES = { FPortecle.RB.getString("KeyStoreTableModel.TypeColumn"),
	    FPortecle.RB.getString("KeyStoreTableModel.ExpiredColumn"),
	    FPortecle.RB.getString("KeyStoreTableModel.AliasColumn"),
	    FPortecle.RB.getString("KeyStoreTableModel.FromDateColumn"),
	    FPortecle.RB.getString("KeyStoreTableModel.ExpiryDateColumn"),
	    FPortecle.RB.getString("KeyStoreTableModel.LastModifiedDateColumn") };

	/** Value to place in the type column for a key pair entry */
	public static final String KEY_PAIR_ENTRY = FPortecle.RB.getString("KeyStoreTableModel.KeyPairEntry");

	/** Value to place in the type column for a trusted certificate entry */
	public static final String TRUST_CERT_ENTRY = FPortecle.RB.getString("KeyStoreTableModel.TrustCertEntry");

	/** Value to place in the type column for a key entry */
	public static final String KEY_ENTRY = FPortecle.RB.getString("KeyStoreTableModel.KeyEntry");
	
	/** Value to place in the expired column for a good certificate */
	public static final String CERT_VALID_OK = FPortecle.RB.getString("KeyStoreTableModel.CertValidOK");
	/** Value to place in the expired column for a certificate that is close to expiration date */
	public static final String CERT_VALID_EXPIRES = FPortecle.RB.getString("KeyStoreTableModel.CertExpires");
	/** Value to place in the expired column for a certificate that has expired */
	public static final String CERT_VALID_EXPIRED = FPortecle.RB.getString("KeyStoreTableModel.CertExpired");
	

	/** Column classes */
	private static final Class<?>[] COLUMN_CLASSES = { String.class, String.class, String.class, Date.class, Date.class, Date.class };

	/** Holds the table data */
	private Object[][] m_data;

	/** Parent Portecle object */
	private final FPortecle portecle;

	/**
	 * Construct a new KeyStoreTableModel.
	 *
	 * @param portecle The parent Portecle frame
	 */
	public KeyStoreTableModel(FPortecle portecle)
	{
		m_data = new Object[0][getColumnCount()];
		this.portecle = portecle;
	}

	/**
	 * Load the KeyStoreTableModel with the entries from a keystore.
	 *
	 * @param keyStore The keystore
	 * @throws KeyStoreException A problem is encountered accessing the keystore's entries
	 */
	public void load(KeyStore keyStore)
	    throws KeyStoreException
	{
		// Does the keystore support creation dates?
		boolean cdSupport = KeyStoreType.valueOfType(keyStore.getType()).isEntryCreationDateUseful();

		// Create one table row for each keystore entry
		m_data = new Object[keyStore.size()][getColumnCount()];
		
		// used in certificate expiration date comparison
		Calendar now = Calendar.getInstance();
		Calendar future60 = Calendar.getInstance();
		future60.add(Calendar.DAY_OF_MONTH, 60); // TODO: make this number of days an option?

		// Iterate through the aliases, retrieving the keystore entries and populating the table model
		int iCnt = 0;
		for (Enumeration<String> en = keyStore.aliases(); en.hasMoreElements();)
		{
			String sAlias = en.nextElement();

			// Populate the type column - it is set with an integer but a custom cell renderer will cause a
			// suitable icon to be displayed
			if (keyStore.isCertificateEntry(sAlias))
			{
				m_data[iCnt][COLUMN_TYPE] = TRUST_CERT_ENTRY;
			}
			else if (keyStore.isKeyEntry(sAlias) && keyStore.getCertificateChain(sAlias) != null &&
			    keyStore.getCertificateChain(sAlias).length != 0)
			{
				m_data[iCnt][COLUMN_TYPE] = KEY_PAIR_ENTRY;
			}
			else
			{
				m_data[iCnt][COLUMN_TYPE] = KEY_ENTRY;
			}

			// Populate the alias column
			m_data[iCnt][COLUMN_ALIAS] = sAlias;

			// Populate the from date and expiry date column for X509Certificates
			try {
				X509Certificate cert =(X509Certificate) keyStore.getCertificate(sAlias);
				
				if(cert!=null)
				{
					m_data[iCnt][COLUMN_DATESTART] = cert.getNotBefore();
					m_data[iCnt][COLUMN_DATEEND] = cert.getNotAfter();
					
					// Populate the expired column - it is set with a string but a custom cell renderer will cause a
					// suitable icon to be displayed
					
					Calendar validUntil =Calendar.getInstance();
					validUntil.setTime(cert.getNotAfter());
					if(now.after(validUntil))
						m_data[iCnt][COLUMN_EXPIRATION] = CERT_VALID_EXPIRED;
					else if(future60.after(validUntil))
						m_data[iCnt][COLUMN_EXPIRATION] = CERT_VALID_EXPIRES;
					else  
						m_data[iCnt][COLUMN_EXPIRATION] = CERT_VALID_OK;
				}
				
			}
			catch(Exception any) { }

			// Populate the modified date column
			if (cdSupport)
			{
				m_data[iCnt][COLUMN_DATELASTMODIFIED] = keyStore.getCreationDate(sAlias);
			}

			iCnt++;
		}

		fireTableDataChanged();
	}

	/**
	 * Get the number of columns in the table.
	 *
	 * @return The number of columns
	 */
	@Override
	public int getColumnCount()
	{
		return COLUMN_CLASSES.length;
	}

	/**
	 * Get the number of rows in the table.
	 *
	 * @return The number of rows
	 */
	@Override
	public int getRowCount()
	{
		return m_data.length;
	}

	/**
	 * Get the name of the column at the given position.
	 *
	 * @param iCol The column position
	 * @return The column name
	 */
	@Override
	public String getColumnName(int iCol)
	{
		return COLUMN_NAMES[iCol];
	}

	/**
	 * Get the cell value at the given row and column position.
	 *
	 * @param iRow The row position
	 * @param iCol The column position
	 * @return The cell value
	 */
	@Override
	public Object getValueAt(int iRow, int iCol)
	{
		return m_data[iRow][iCol];
	}

	@Override
	public void setValueAt(Object value, int rowIndex, int columnIndex)
	{
		if (isCellEditable(rowIndex, columnIndex))
		{
			portecle.renameEntry(m_data[rowIndex][columnIndex].toString(), value.toString(), true);
		}
	}

	/**
	 * Get the class at of the cells at the given column position.
	 *
	 * @param iCol The column position
	 * @return The column cells' class
	 */
	@Override
	public Class<?> getColumnClass(int iCol)
	{
		return COLUMN_CLASSES[iCol];
	}

	/**
	 * Is the cell at the given row and column position editable?
	 *
	 * @param iRow The row position
	 * @param iCol The column position
	 * @return True if the cell is editable, false otherwise
	 */
	@Override
	public boolean isCellEditable(int iRow, int iCol)
	{
		if (iCol != COLUMN_ALIAS)
		{
			return false;
		}

		// Key-only entries are not renameable - we do a remove-store operation but the KeyStore API won't
		// allow us to store a PrivateKey without associated certificate chain.
		// TODO: Maybe it'd work for other Key types? Need testing material.
		return !KEY_ENTRY.equals(m_data[iRow][COLUMN_TYPE]);
	}
}
