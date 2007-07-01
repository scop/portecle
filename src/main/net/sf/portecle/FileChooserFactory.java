/*
 * FileChooserFactory.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004-2007 Ville Skyttä, ville.skytta@iki.fi
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
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.ResourceBundle;
import java.util.regex.Pattern;

import javax.swing.JFileChooser;

import net.sf.portecle.crypto.KeyStoreType;
import net.sf.portecle.crypto.KeyStoreUtil;
import net.sf.portecle.gui.FileExtFilter;

/**
 * Simple factory that returns JFileChooser objects for the requested
 * security file types. Basically just supplies a JFileChooser object
 * with the file filter box completed appropriately.
 */
public class FileChooserFactory
{
    /** Resource bundle */
    private static ResourceBundle m_res = ResourceBundle.getBundle("net/sf/portecle/resources");

    /** File extension for keystore files */
    private static final String KEYSTORE_EXT = "ks";

    /** File extension for X.509 certificate files */
    private static final String X509_EXT_1 = "cer";

    /** File extension for X.509 certificate files */
    private static final String X509_EXT_2 = "crt";

    /** File extension for PKCS #7 certificate files */
    private static final String PKCS7_EXT = "p7b";

    /** File extension for PkiPath certificate files */
    private static final String PKIPATH_EXT = "pkipath";

    /** File extension for PEM files */
    private static final String PEM_EXT = "pem";

    /** File extension for PKCS #10 CSR files */
    private static final String CSR_EXT_1 = "p10";

    /** File extension for PKCS #10 CSR files */
    private static final String CSR_EXT_2 = "csr";

    /** File extension for CRL files */
    private static final String CRL_EXT = "crl";

    /** Description for X.509 certificate files */
    private static final String X509_FILE_DESC = MessageFormat.format(
        m_res.getString("FileChooseFactory.CertificateFiles"),
        toWildcards(new String[] { X509_EXT_1, X509_EXT_2 }));

    /** Description for PKCS #7 certificate files */
    private static final String PKCS7_FILE_DESC = MessageFormat.format(
        m_res.getString("FileChooseFactory.Pkcs7Files"),
        toWildcards(new String[] { PKCS7_EXT }));

    /** Description for PkiPath certificate files */
    private static final String PKIPATH_FILE_DESC = MessageFormat.format(
        m_res.getString("FileChooseFactory.PkiPathFiles"),
        toWildcards(new String[] { PKIPATH_EXT }));

    /** Description for PEM files */
    private static final String PEM_FILE_DESC = MessageFormat.format(
        m_res.getString("FileChooseFactory.PEMFiles"),
        toWildcards(new String[] { PEM_EXT }));

    /** Description for PKCS #10 CSR files */
    private static final String CSR_FILE_DESC = MessageFormat.format(
        m_res.getString("FileChooseFactory.CsrFiles"),
        toWildcards(new String[] { CSR_EXT_1, CSR_EXT_2 }));

    /** Description for CRL files */
    private static final String CRL_FILE_DESC = MessageFormat.format(
        m_res.getString("FileChooseFactory.CrlFiles"),
        toWildcards(new String[] { CRL_EXT }));

    /** Filename filter pattern for getDefaultFile() */
    private static final Pattern FILENAME_FILTER = Pattern.compile("[^\\p{L}_\\-]+");

    /** Separator to use in informational file name lists */
    private static final String FILELIST_SEPARATOR = ";";
    
    /** Filename of the default CA certs keystore. */
    public static final String CACERTS_FILENAME = "cacerts";
    
    /** Private to prevent construction */
    private FileChooserFactory()
    {
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
        
        if (ksType == null) {
            ArrayList exts = new ArrayList();
            exts.add(KEYSTORE_EXT);
            if (KeyStoreUtil.isAvailable(KeyStoreType.JKS)) {
                exts.addAll(Arrays.asList(KeyStoreType.JKS.getFilenameExtensions()));
                // Assume includes CaseExactJKS
            }
            if (KeyStoreUtil.isAvailable(KeyStoreType.JCEKS)) {
                exts.addAll(Arrays.asList(KeyStoreType.JCEKS.getFilenameExtensions()));
            }
            exts.addAll(Arrays.asList(KeyStoreType.PKCS12.getFilenameExtensions()));
            exts.addAll(Arrays.asList(KeyStoreType.BKS.getFilenameExtensions()));
            exts.addAll(Arrays.asList(KeyStoreType.UBER.getFilenameExtensions()));
            if (KeyStoreUtil.isAvailable(KeyStoreType.GKR)) {
                exts.addAll(Arrays.asList(KeyStoreType.GKR.getFilenameExtensions()));
            }
            extensions = (String[]) exts.toArray(new String[exts.size()]);
            String[] info = toWildcards(extensions);
            info[0] += FILELIST_SEPARATOR + CACERTS_FILENAME;
            desc = MessageFormat.format(
                m_res.getString("FileChooseFactory.KeyStoreFiles"), info);
            addCaCerts = true;
        }
        else {
            extensions = ksType.getFilenameExtensions();
            String[] info = toWildcards(extensions);
            if (ksType.equals(KeyStoreType.JKS)) {
                info[0] += FILELIST_SEPARATOR + CACERTS_FILENAME;
                addCaCerts = true;
            }
            desc = MessageFormat.format(
                m_res.getString("FileChooseFactory.KeyStoreFiles."
                    + ksType.toString()), info);
        }
        
        FileExtFilter extFilter;
        if (addCaCerts) {
            extFilter = new FileExtFilter(extensions, desc)
            {
                public boolean accept(File file)
                {
                    return super.accept(file)
                        || file.getName().equalsIgnoreCase(CACERTS_FILENAME);
                }
            };
        }
        else {
            extFilter = new FileExtFilter(extensions, desc);
        }
        
        chooser.addChoosableFileFilter(extFilter);

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
        chooser.addChoosableFileFilter(new FileExtFilter(new String[] {
            X509_EXT_1, X509_EXT_2 }, X509_FILE_DESC));
        chooser.setSelectedFile(getDefaultFile(basename, X509_EXT_1));
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
        chooser.addChoosableFileFilter(new FileExtFilter(PKCS7_EXT,
            PKCS7_FILE_DESC));
        chooser.setSelectedFile(getDefaultFile(basename, PKCS7_EXT));
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
        chooser.addChoosableFileFilter(new FileExtFilter(PKIPATH_EXT,
            PKIPATH_FILE_DESC));
        chooser.setSelectedFile(getDefaultFile(basename, PKIPATH_EXT));
        return chooser;
    }

    /**
     * Get a JFileChooser filtered for X.509, PKCS #7, and PkiPath
     * Certificate files.
     *
     * @return JFileChooser object
     */
    public static JFileChooser getCertFileChooser()
    {
        JFileChooser chooser = new JFileChooser();
        chooser.addChoosableFileFilter(new FileExtFilter(PKCS7_EXT,
            PKCS7_FILE_DESC));
        chooser.addChoosableFileFilter(new FileExtFilter(PKIPATH_EXT,
            PKIPATH_FILE_DESC));
        chooser.addChoosableFileFilter(new FileExtFilter(new String[] {
            X509_EXT_1, X509_EXT_2 }, X509_FILE_DESC));
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
        String[] exts = KeyStoreType.PKCS12.getFilenameExtensions();
        assert exts.length > 1;
        chooser.setSelectedFile(getDefaultFile(basename, exts[0]));
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
        chooser.addChoosableFileFilter(new FileExtFilter(
            new String[] { PEM_EXT }, PEM_FILE_DESC));
        chooser.setSelectedFile(getDefaultFile(basename, PEM_EXT));
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
        chooser.addChoosableFileFilter(new FileExtFilter(new String[] {
            CSR_EXT_1, CSR_EXT_2 }, CSR_FILE_DESC));
        chooser.setSelectedFile(getDefaultFile(basename, CSR_EXT_2));
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
        chooser.addChoosableFileFilter(new FileExtFilter(CRL_EXT,
            CRL_FILE_DESC));
        return chooser;
    }

    /**
     * Gets a default file based on the basename and extension,
     * filtering uncomfortable characters.
     * 
     * @param basename base filename (without extension) 
     * @param extension the extension
     * @return a file named by deriving from basename, null if a
     * sane name can't be worked out
     */
    private static File getDefaultFile(String basename, String extension)
    {
        if (basename == null) {
            return null;
        }
        basename = FILENAME_FILTER.matcher(basename.trim()).replaceAll("_");
        basename = basename.replaceAll("_+", "_");
        basename = basename.replaceFirst("^_+", "");
        basename = basename.replaceFirst("_+$", "");
        if (basename.length() > 0) {
            return new File(basename + "." + extension);
        }
        return null;
    }
    
    /**
     * Converts an array of filename extensions into a (informational)
     * filename match pattern.
     * @param exts
     * @return string array of length 1 (for easy use with message formatting)
     */
    private static String[] toWildcards(String[] exts)
    {
        StringBuffer res = new StringBuffer();
        for (int i = 0, len = exts.length; i < len; i++) {
            res.append("*.").append(exts[i]).append(FILELIST_SEPARATOR);
        }
        res.setLength(res.length() - FILELIST_SEPARATOR.length());
        return new String[] { res.toString() };
    }
}
