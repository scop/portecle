/*
 * FileChooserFactory.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004-2008 Ville Skyttä, ville.skytta@iki.fi
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

import static net.sf.portecle.FPortecle.RB;

import java.awt.Toolkit;
import java.io.File;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileView;

import net.sf.portecle.crypto.KeyStoreType;
import net.sf.portecle.crypto.KeyStoreUtil;
import net.sf.portecle.gui.FileExtFilter;

/**
 * Simple factory that returns JFileChooser objects for the requested security file types. Basically just supplies a
 * JFileChooser object with the file filter box completed appropriately.
 */
/* package private */class FileChooserFactory
{
	/** File extension for keystore files */
	private static final String KEYSTORE_EXT = "ks";

	/** File extension for PEM files */
	private static final String PEM_EXT = "pem";

	/** File extensions for PKCS #7 certificate files */
	private static final String[] PKCS7_EXTS = { "p7b", "spc" };

	/** File extensions for PkiPath certificate files */
	private static final String[] PKIPATH_EXTS = { "pkipath" };

	/** File extensions for X.509 certificate files */
	private static final String[] X509_EXTS = { "cer", "crt", "cert", PEM_EXT };

	/** File extensions for certificate files */
	/* package private */static final String[] CERT_EXTS =
	    { X509_EXTS[0], X509_EXTS[1], X509_EXTS[2], PEM_EXT, PKCS7_EXTS[0], PKCS7_EXTS[1], PKIPATH_EXTS[0] };

	/** File extensions for certificate request files */
	/* package private */static final String[] CSR_EXTS = { "csr", "p10", PEM_EXT };

	/** File extensions for certificate revocation list files */
	/* package private */static final String[] CRL_EXTS = { "crl" };

	/** Description for X.509 certificate files */
	private static final String X509_FILE_DESC =
	    MessageFormat.format(RB.getString("FileChooseFactory.X509Files"), toWildcards(X509_EXTS));

	/** Description for PKCS #7 certificate files */
	private static final String PKCS7_FILE_DESC =
	    MessageFormat.format(RB.getString("FileChooseFactory.Pkcs7Files"), toWildcards(PKCS7_EXTS));

	/** Description for PkiPath certificate files */
	private static final String PKIPATH_FILE_DESC =
	    MessageFormat.format(RB.getString("FileChooseFactory.PkiPathFiles"), toWildcards(PKIPATH_EXTS));

	/** Description for PEM files */
	private static final String PEM_FILE_DESC =
	    MessageFormat.format(RB.getString("FileChooseFactory.PEMFiles"), toWildcards(new String[] { PEM_EXT }));

	/** Description for files containing key pairs */
	private static final String KEYPAIR_FILE_DESC;

	static
	{
		LinkedHashSet<String> exts = new LinkedHashSet<>();
		exts.addAll(KeyStoreType.PKCS12.getFilenameExtensions());
		exts.add(PEM_EXT);
		KEYPAIR_FILE_DESC = MessageFormat.format(RB.getString("FileChooseFactory.KeyPairFiles"),
		    toWildcards(exts.toArray(new String[exts.size()])));
	}

	/** Description for PKCS #10 CSR files */
	private static final String CSR_FILE_DESC =
	    MessageFormat.format(RB.getString("FileChooseFactory.CsrFiles"), toWildcards(CSR_EXTS));

	/** Description for CRL files */
	private static final String CRL_FILE_DESC =
	    MessageFormat.format(RB.getString("FileChooseFactory.CrlFiles"), toWildcards(CRL_EXTS));

	/** Description for certificate files */
	private static final String CERT_FILE_DESC =
	    MessageFormat.format(RB.getString("FileChooseFactory.CertificateFiles"), toWildcards(CERT_EXTS));

	/** Filename filter pattern for getDefaultFile() */
	private static final Pattern FILENAME_FILTER = Pattern.compile("[^\\p{L}_\\-]+");

	/** Separator to use in informational file name lists */
	private static final String FILELIST_SEPARATOR = ";";

	/** Filename of the default CA certificates keystore. */
	/* package private */static final String CACERTS_FILENAME = "cacerts";

	/** Private to prevent construction */
	private FileChooserFactory()
	{
		// Nothing to do
	}

	/**
	 * Get a JFileChooser filtered for keystore files.
	 * 
	 * @param ksType Type to filter for, all supported if null
	 * @return JFileChooser object
	 */
	public static JFileChooser getKeyStoreFileChooser(KeyStoreType ksType)
	{
		JFileChooser chooser = new JFileChooser();

		String[] extensions;
		String desc;
		// Whether we plug in "cacerts"
		boolean addCaCerts = false;

		if (ksType == null)
		{
			ArrayList<String> exts = new ArrayList<>();
			exts.add(KEYSTORE_EXT);
			if (KeyStoreUtil.isAvailable(KeyStoreType.JKS))
			{
				exts.addAll(KeyStoreType.JKS.getFilenameExtensions());
				// Assume includes CaseExactJKS
			}
			if (KeyStoreUtil.isAvailable(KeyStoreType.JCEKS))
			{
				exts.addAll(KeyStoreType.JCEKS.getFilenameExtensions());
			}
			exts.addAll(KeyStoreType.PKCS12.getFilenameExtensions());
			exts.addAll(KeyStoreType.BKS.getFilenameExtensions());
			exts.addAll(KeyStoreType.UBER.getFilenameExtensions());
			if (KeyStoreUtil.isAvailable(KeyStoreType.GKR))
			{
				exts.addAll(KeyStoreType.GKR.getFilenameExtensions());
			}
			extensions = exts.toArray(new String[exts.size()]);
			String info = toWildcards(extensions) + FILELIST_SEPARATOR + CACERTS_FILENAME;
			desc = MessageFormat.format(RB.getString("FileChooseFactory.KeyStoreFiles"), info);
			addCaCerts = true;
		}
		else
		{
			extensions = ksType.getFilenameExtensions().toArray(new String[0]);
			String info = toWildcards(extensions);
			if (ksType == KeyStoreType.JKS)
			{
				info += FILELIST_SEPARATOR + CACERTS_FILENAME;
				addCaCerts = true;
			}
			desc = MessageFormat.format(RB.getString("FileChooseFactory.KeyStoreFiles." + ksType.name()), info);
		}

		FileExtFilter extFilter;
		if (addCaCerts)
		{
			extFilter = new FileExtFilter(extensions, desc)
			{
				@Override
				public boolean accept(File file)
				{
					return super.accept(file) || file.getName().equalsIgnoreCase(CACERTS_FILENAME);
				}
			};
		}
		else
		{
			extFilter = new FileExtFilter(extensions, desc);
		}

		chooser.addChoosableFileFilter(extFilter);
		chooser.setFileFilter(extFilter);
		chooser.setFileView(new PortecleFileView());

		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for X.509 Certificate files.
	 * 
	 * @param basename default filename (without extension)
	 * @return JFileChooser object
	 */
	public static JFileChooser getX509FileChooser(String basename)
	{
		JFileChooser chooser = new JFileChooser();
		FileExtFilter extFilter = new FileExtFilter(X509_EXTS, X509_FILE_DESC);
		chooser.addChoosableFileFilter(extFilter);
		chooser.setFileFilter(extFilter);
		chooser.setSelectedFile(getDefaultFile(basename, X509_EXTS[0]));
		chooser.setFileView(new PortecleFileView());
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for PKCS #7 Certificate files.
	 * 
	 * @param basename default filename (without extension)
	 * @return JFileChooser object
	 */
	public static JFileChooser getPkcs7FileChooser(String basename)
	{
		JFileChooser chooser = new JFileChooser();
		FileExtFilter extFilter = new FileExtFilter(PKCS7_EXTS, PKCS7_FILE_DESC);
		chooser.addChoosableFileFilter(extFilter);
		chooser.setFileFilter(extFilter);
		chooser.setSelectedFile(getDefaultFile(basename, PKCS7_EXTS[0]));
		chooser.setFileView(new PortecleFileView());
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for PkiPath Certificate files.
	 * 
	 * @param basename default filename (without extension)
	 * @return JFileChooser object
	 */
	public static JFileChooser getPkiPathFileChooser(String basename)
	{
		JFileChooser chooser = new JFileChooser();
		FileExtFilter extFilter = new FileExtFilter(PKIPATH_EXTS, PKIPATH_FILE_DESC);
		chooser.addChoosableFileFilter(extFilter);
		chooser.setFileFilter(extFilter);
		chooser.setSelectedFile(getDefaultFile(basename, PKIPATH_EXTS[0]));
		chooser.setFileView(new PortecleFileView());
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for X.509, PKCS #7, and PkiPath Certificate files.
	 * 
	 * @return JFileChooser object
	 */
	public static JFileChooser getCertFileChooser()
	{
		JFileChooser chooser = new JFileChooser();
		FileExtFilter extFilter = new FileExtFilter(CERT_EXTS, CERT_FILE_DESC);
		chooser.addChoosableFileFilter(extFilter);
		chooser.setFileFilter(extFilter);
		chooser.setFileView(new PortecleFileView());
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for PKCS #12 files.
	 * 
	 * @param basename default filename (without extension)
	 * @return JFileChooser object
	 */
	public static JFileChooser getPkcs12FileChooser(String basename)
	{
		JFileChooser chooser = getKeyStoreFileChooser(KeyStoreType.PKCS12);
		Set<String> exts = KeyStoreType.PKCS12.getFilenameExtensions();
		assert exts.size() > 1;
		chooser.setSelectedFile(getDefaultFile(basename, exts.iterator().next()));
		chooser.setFileView(new PortecleFileView());
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for PEM files.
	 * 
	 * @param basename default filename (without extension)
	 * @return JFileChooser object
	 */
	public static JFileChooser getPEMFileChooser(String basename)
	{
		JFileChooser chooser = new JFileChooser();
		FileExtFilter extFilter = new FileExtFilter(PEM_EXT, PEM_FILE_DESC);
		chooser.addChoosableFileFilter(extFilter);
		chooser.setFileFilter(extFilter);
		chooser.setSelectedFile(getDefaultFile(basename, PEM_EXT));
		chooser.setFileView(new PortecleFileView());
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for PKCS #12 and PEM files.
	 * 
	 * @param basename default filename (without extension)
	 * @return JFileChooser object
	 */
	public static JFileChooser getKeyPairFileChooser(String basename)
	{
		JFileChooser chooser = new JFileChooser();
		LinkedHashSet<String> exts = new LinkedHashSet<>();
		exts.addAll(KeyStoreType.PKCS12.getFilenameExtensions());
		exts.add(PEM_EXT);
		FileExtFilter extFilter = new FileExtFilter(exts.toArray(new String[exts.size()]), KEYPAIR_FILE_DESC);
		chooser.addChoosableFileFilter(extFilter);
		chooser.setFileFilter(extFilter);
		chooser.setSelectedFile(getDefaultFile(basename, exts.iterator().next()));
		chooser.setFileView(new PortecleFileView());
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for CSR files.
	 * 
	 * @param basename default filename (without extension)
	 * @return JFileChooser object
	 */
	public static JFileChooser getCsrFileChooser(String basename)
	{
		JFileChooser chooser = new JFileChooser();
		FileExtFilter extFilter = new FileExtFilter(CSR_EXTS, CSR_FILE_DESC);
		chooser.addChoosableFileFilter(extFilter);
		chooser.setFileFilter(extFilter);
		chooser.setSelectedFile(getDefaultFile(basename, CSR_EXTS[0]));
		chooser.setFileView(new PortecleFileView());
		return chooser;
	}

	/**
	 * Get a JFileChooser filtered for CRL files.
	 * 
	 * @return JFileChooser object
	 */
	public static JFileChooser getCrlFileChooser()
	{
		JFileChooser chooser = new JFileChooser();
		FileExtFilter extFilter = new FileExtFilter(CRL_EXTS, CRL_FILE_DESC);
		chooser.addChoosableFileFilter(extFilter);
		chooser.setFileFilter(extFilter);
		chooser.setFileView(new PortecleFileView());
		return chooser;
	}

	/**
	 * Gets a default file based on the base name and extension, filtering uncomfortable characters.
	 * 
	 * @param basename base filename (without extension)
	 * @param extension the extension
	 * @return a file named by deriving from base name, null if a sane name can't be worked out
	 */
	private static File getDefaultFile(String basename, String extension)
	{
		if (basename == null)
		{
			return null;
		}
		basename = FILENAME_FILTER.matcher(basename.trim()).replaceAll("_");
		basename = basename.replaceAll("_+", "_");
		basename = basename.replaceFirst("^_+", "");
		basename = basename.replaceFirst("_+$", "");
		if (!basename.isEmpty())
		{
			return new File(basename + "." + extension);
		}
		return null;
	}

	/**
	 * Converts an array of filename extensions into a (informational) filename match pattern.
	 * 
	 * @param exts
	 * @return informational filename match pattern
	 */
	private static String toWildcards(String[] exts)
	{
		StringBuilder res = new StringBuilder();
		for (String ext : exts)
		{
			res.append("*.").append(ext).append(FILELIST_SEPARATOR);
		}
		res.setLength(res.length() - FILELIST_SEPARATOR.length());
		return res.toString();
	}

	/**
	 * FileView for showing keystore, certificate etc files.
	 */
	private static class PortecleFileView
	    extends FileView
	{
		private static final Icon CERTIFICATE_ICON = new ImageIcon(Toolkit.getDefaultToolkit().createImage(
		    FileChooserFactory.class.getResource(RB.getString("FileChooseFactory.CertificateImage"))));

		private static final Icon KEYSTORE_ICON = new ImageIcon(Toolkit.getDefaultToolkit().createImage(
		    FileChooserFactory.class.getResource(RB.getString("FileChooseFactory.KeyStoreImage"))));

		private static final Icon CRL_ICON = new ImageIcon(Toolkit.getDefaultToolkit().createImage(
		    FileChooserFactory.class.getResource(RB.getString("FileChooseFactory.CrlImage"))));

		private static final Icon CSR_ICON = new ImageIcon(Toolkit.getDefaultToolkit().createImage(
		    FileChooserFactory.class.getResource(RB.getString("FileChooseFactory.CsrImage"))));

		@Override
		public Icon getIcon(File f)
		{
			// The f.isDirectory() check is superfluous here, but it reportedly avoids some odd
			// delays on Windows (sf.net#3129497).
			if (f.isDirectory() || !f.isFile())
			{
				return super.getIcon(f);
			}

			String fn = f.getName().toLowerCase(Locale.ENGLISH);

			for (String ext : KeyStoreType.getKeyStoreFilenameExtensions())
			{
				if (fn.endsWith("." + ext) || fn.equals("cacerts"))
				{
					return KEYSTORE_ICON;
				}
			}

			for (String ext : CERT_EXTS)
			{
				if (fn.endsWith("." + ext))
				{
					return CERTIFICATE_ICON;
				}
			}

			for (String ext : CSR_EXTS)
			{
				if (fn.endsWith("." + ext))
				{
					return CSR_ICON;
				}
			}

			for (String ext : CRL_EXTS)
			{
				if (fn.endsWith("." + ext))
				{
					return CRL_ICON;
				}
			}

			return super.getIcon(f);
		}
	}
}
