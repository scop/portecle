/*
 * XmlEncodingUtil.java
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

package net.sf.portecle.xml;

import java.io.*;

/**
 * Utility class for methods related to XML encoding.
 */
public class XmlEncodingUtil extends Object
{
    /** UTF-8 encoding name */
    public static final String UTF8 = "UTF-8";

    /** UTF-16 encoding name */
    public static final String UTF16 = "UTF-16";

    /** UTF-16, big endian encoding name */
    public static final String UTF16BE = "UTF-16BE";

    /** UTF-16, big little encoding name */
    public static final String UTF16LE = "UTF-16LE";

    /** Start of an XML declaration */
    private static final String START_XML_DECL = "<?xml ";

    /**
     * Private to prevent construction.
     */
    private XmlEncodingUtil() {}

    /**
     * Detect an XML file's encoding as either UTF-16BE, UTF-16LE, UTF-8, etc.
     * If a byte-order mark is found UTF-16xx is returned.  Alternatively UTF-8
     * is assumed unless the XML declaration's encoding attribute says different.
     *
     * @param fXml The file
     * @return The encoding
     * @throws IOException if an I/O problem occurs
     */
    public static String getEncoding(File fXml) throws IOException
    {
        FileInputStream fis = null;
        BufferedReader br = null;
        String sEncoding = null;

        try
        {
            // Read first two bytes from file
            fis = new FileInputStream(fXml);

            int i1 = fis.read();
            int i2 = fis.read();

            // Do we have two-bytes?
            if ((i1 != -1) && (i2 != -1))
            {
                byte b1 = (byte)i1;
                byte b2 = (byte)i2;

                if (((b1 & 0xff) == 0xfe) && ((b2 & 0xff) == 0xff))
                {
                    // UTF-16, big-endian
                    sEncoding = UTF16BE;
                }
                else if (((b1 & 0xff) == 0xff) && ((b2 & 0xff) == 0xfe))
                {
                    // UTF-16, little-endian
                    sEncoding = UTF16LE;
                }
                else
                {
                    // Assume UTF-8 until xml declaration tells us different
                    sEncoding = UTF8;

                    fis.close();

                    br = new BufferedReader(new InputStreamReader(new FileInputStream(fXml), UTF8));

                    // Read first 100 characters of the file
                    char[] cBuff = new char[100];
                    int iRead = br.read(cBuff, 0, cBuff.length);
                    if (iRead != -1)
                    {
                        // Get encoding
                        String sTmp = getEncoding(new String(cBuff, 0, iRead));

                        if (sTmp != null)
                        {
                            return sTmp;
                        }
                    }
                }
            }
            else
            {
                // Not even 2 bytes available in file
                sEncoding = UTF8;
            }
        }
        finally // Clean-up I/O
        {
            if (fis != null)
            {
                try { fis.close(); } catch (IOException ex) { /* Ignore */ }
            }

            if (br != null)
            {
                try { br.close(); } catch (IOException ex) { /* Ignore */ }
            }
        }
        return sEncoding;
    }

    /**
     * Extract the encoding attribute's value from the supplied XML.
     *
     * @param sXml The XML
     * @return Encoding attribute's value or null if none is found
     * @throws IOException If there is a problem extracting the encoding attribute's value
     */
    public static String getEncoding(String sXml) throws IOException
    {
        StringReader sr = null;
        char[] cBuffer = null;
        char c = 0;
        int iRead = 0;

        try
        {
            sr = new StringReader(sXml);
            cBuffer = new char[START_XML_DECL.length()];

            // Check for '<?xml ' at the start
            iRead = sr.read(cBuffer, 0, cBuffer.length);

            if ((iRead == cBuffer.length) && (START_XML_DECL.equals(new String(cBuffer))))
            {
                // While not end of string
                while (iRead != -1)
                {
                    iRead = sr.read();

                    // Skip white space
                    while ((iRead != -1) && (Character.isWhitespace((char)iRead)))
                    {
                        iRead = sr.read();
                    }

                    // Read an attribute name
                    StringBuffer sbAttrName = new StringBuffer();
                    while ((iRead != -1) && (Character.isLetter((char)iRead)))
                    {
                        sbAttrName.append((char)iRead);
                        iRead = sr.read();
                    }
                    String sAttrName = sbAttrName.toString();

                    // Skip white space
                    while ((iRead != -1) && (Character.isWhitespace((char)iRead)))
                    {
                        iRead = sr.read();
                    }

                    // Read equals
                    if (iRead == '=')
                    {
                        iRead = sr.read();

                        // Skip white space
                        while ((iRead != -1) && (Character.isWhitespace((char)iRead)))
                        {
                            iRead = sr.read();
                        }

                        // Read an attribute value
                        StringBuffer sbAttrValue = new StringBuffer();

                        if ((iRead == '\'') || (iRead == '"'))
                        {
                            char cQuote = (char)iRead;

                            iRead = sr.read();

                            while ((iRead != -1) && (iRead != cQuote))
                            {
                                sbAttrValue.append((char)iRead);
                                iRead = sr.read();
                            }
                        }
                        String sAttrValue = sbAttrValue.toString();

                        // If name is "encoding" return the attribute value
                        if (sAttrName.equals("encoding"))
                        {
                            return sAttrValue;
                        }
                    }
                }
            }
        }
        finally
        {
            if (sr != null)
            {
                sr.close();
            }
        }

        return null;
    }
}
