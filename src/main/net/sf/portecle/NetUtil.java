/*
 * NetUtil.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2008 Ville Skyttä, ville.skytta@iki.fi
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

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Networking utilities.
 * 
 * @author Ville Skyttä
 */
public final class NetUtil
{
	/** Logger */
	private static final Logger LOG = Logger.getLogger(NetUtil.class.getCanonicalName());

	// TODO: make this configurable
	private static final int CONNECT_TIMEOUT = 10000;

	// TODO: make this configurable
	private static final int READ_TIMEOUT = 20000;

	/**
	 * Private to prevent construction.
	 */
	private NetUtil()
	{
		// Nothing to do
	}

	/**
	 * Open an input stream to a GET(-like) operation on an URL.
	 * 
	 * @param url The URL
	 * @return Input stream to the URL connection
	 * @throws IOException If an I/O error occurs
	 */
	public static InputStream openGetStream(URL url)
	    throws IOException
	{
		URLConnection conn = url.openConnection();

		conn.setConnectTimeout(CONNECT_TIMEOUT);
		conn.setReadTimeout(READ_TIMEOUT);

		// TODO: User-Agent?

		return conn.getInputStream();
	}

	/**
	 * Open an input stream to a POST(-like) operation on an URL.
	 * 
	 * @param url The URL
	 * @param content Content to POST
	 * @param contentType Content type
	 * @return Input stream to the URL connection
	 * @throws IOException If an I/O error occurs
	 */
	public static InputStream openPostStream(URL url, byte[] content, String contentType)
	    throws IOException
	{
		URLConnection conn = url.openConnection();
		conn.setDoOutput(true);

		conn.setConnectTimeout(CONNECT_TIMEOUT);
		conn.setReadTimeout(READ_TIMEOUT);

		// TODO: User-Agent?

		if (contentType != null)
		{
			conn.setRequestProperty("Content-Type", contentType);
		}

		conn.setRequestProperty("Content-Length", String.valueOf(content.length));

		try (OutputStream out = conn.getOutputStream())
		{
			out.write(content);
		}

		return conn.getInputStream();
	}

	/**
	 * Download the given URL to a temporary local file. The temporary file is marked for deletion at exit.
	 * 
	 * @param url
	 * @return URL pointing to the temporary file, <code>url</code> itself if it's a file: one.
	 * @throws IOException
	 */
	public static URL download(URL url)
	    throws IOException
	{
		if ("file".equals(url.getProtocol()))
		{
			return url;
		}

		File tempFile = null;

		try (InputStream in = openGetStream(url))
		{
			tempFile = File.createTempFile("portecle", null);
			try (OutputStream out = new BufferedOutputStream(new FileOutputStream(tempFile)))
			{
				byte[] buf = new byte[2048];
				int n;
				while ((n = in.read(buf)) != -1)
				{
					out.write(buf, 0, n);
				}
			}
		}
		catch (IOException e)
		{
			if (tempFile != null && !tempFile.delete())
			{
				LOG.log(Level.WARNING, "Could not delete temporary file " + tempFile);
			}
			throw e;
		}

		tempFile.deleteOnExit();

		return tempFile.toURI().toURL();
	}

	/**
	 * Creates a URL pointing to a URL, URI or a File object.
	 * 
	 * @param obj Object to create a URI to
	 * @return URL
	 * @throws ClassCastException if obj is not a supported object
	 * @throws MalformedURLException if converting obj to a URL fails
	 */
	/* default */static URL toURL(Object obj)
	    throws MalformedURLException
	{
		if (obj instanceof File)
		{
			return ((File) obj).toURI().toURL();
		}
		else if (obj instanceof URI)
		{
			return ((URI) obj).toURL();
		}
		else
		{
			return (URL) obj;
		}
	}
}
