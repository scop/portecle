/*
 * RedirectParser.java
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

import javax.swing.text.*;
import javax.swing.text.html.*;
import java.io.*;
import java.net.*;
import java.util.*;

/**
 * Parses an HTML file for a frame redirection.  Used to get through
 * the EasySpace redirection currently setup for the KeyTool GUI site.
 */
public class RedirectParser extends HTMLEditorKit
{

    /**
     * Get a redirection URL.
     *
     * @param urlConnection URL connection of HTML file
     * @return Redirection URL or null if none could be found
     * @throws IOException If a problem is enciuntered parsing for the redirection URL
     */
    public static URL getRedirectUrl(HttpURLConnection urlConnection) throws IOException
    {
        // Create parser and handler
        HTMLEditorKit.Parser m_parser = new RedirectParser().getParser();
        RedirectionParserHandler m_handler = new RedirectionParserHandler();

        InputStreamReader isr = null;

        try
        {
            // Read in HTML file and parse it
            isr = new InputStreamReader(urlConnection.getInputStream());
            m_parser.parse(isr, m_handler, true);

            String sRedirectUrl = m_handler.getRedirectUrl();

            if (sRedirectUrl != null)
            {
                // Got a redirection URL
                return new URL(sRedirectUrl);
            }
            else
            {
                // No redirection URL found
                return null;
            }
        }
        finally
        {
            // Clean up
            if (isr != null)
            {
                try { isr.close(); } catch (IOException ex) { /* Ignore */ }
            }
        }
    }
}

/**
 * Parser handler.  Gets and stores the src for the first frame tag it finds
 * as the redirection URL.
 */
class RedirectionParserHandler extends HTMLEditorKit.ParserCallback
{
    /** Redirection URL */
    private String m_sRedirectUrl;

    /**
     * Called whenever a simple tag is encountered by the parser.
     * If the tag is teh first frame tag encountered with a src
     * attribute this is stored as the redirection URL.
     *
     * @param tag Tag
     * @param attrs Tag attributes
     * @param iPosition Position
     */
    public void handleSimpleTag(HTML.Tag tag, MutableAttributeSet attrs, int iPosition)
    {
        if (m_sRedirectUrl == null)
        {
            if (tag.toString().equalsIgnoreCase("frame"))
            {
                for (Enumeration attrNames = attrs.getAttributeNames(); attrNames.hasMoreElements();)
                {
                    HTML.Attribute attrName = (HTML.Attribute)attrNames.nextElement();

                    if (attrName.toString().equalsIgnoreCase("src"))
                    {
                        m_sRedirectUrl = (String)attrs.getAttribute(attrName);
                    }
                }
            }
        }
    }

    /**
     * Get any redirection URL found by the parser handler.
     *
     * @return Redirection URL or null if none found.
     */
    public String getRedirectUrl()
    {
        return m_sRedirectUrl;
    }
}
