/*
 * LastDir.java
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

package net.sf.portecle.gui;

import java.io.File;

/**
 * Simple class intended to store the last accessed directory for a file
 * centric GUI application.
 */
public class LastDir
{
    /** Last directory. */
    private File m_fLastDir;

    /**
     * Construct an empty LastDir object.
     */
    public LastDir()
    {
    }

    /**
     * Construct a LastDir object based on the supplied file.
     *
     * @param file Used to set last directory
     */
    public LastDir(File file)
    {
        m_fLastDir = new File(file.toString());
    }

    /**
     * Update the LastDir object based on the supplied file.
     * If the file exists and is a directory it is used,
     * if it exists and is a regular file then its parent
     * is used.
     *
     * @param file Used to set last directory
     */
    public void updateLastDir(File file)
    {
        if (file != null && file.exists())
        {
            m_fLastDir = file.isDirectory() ? file : file.getParentFile();
        }
    }

    /**
     * Get the last updated directory.
     *
     * @return Last directory if the last update still exists, false otherwise
     */
    public File getLastDir()
    {
        if (m_fLastDir != null && m_fLastDir.exists()) {
            return new File(m_fLastDir.toString());
        }
        return null;
    }
}
