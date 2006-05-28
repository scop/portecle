/*
 * LightMetalTheme.java
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package net.sf.portecle.gui.theme;

import java.awt.Font;

import javax.swing.plaf.FontUIResource;
import javax.swing.plaf.metal.DefaultMetalTheme;

/**
 * Very simple Metal theme that simply gets rid of the bold used in the default
 * theme for control and menu text (note: title is left bold).
 */
public class LightMetalTheme
    extends DefaultMetalTheme
{
    /** Theme name */
    private static final String THEME_NAME = "Light Metal";

    /**
     * Get theme name.
     *
     * @return Theme name
     */
    public String getName()
    {
        return THEME_NAME;
    }

    /**
     * Get control text font - minus the usual bold.
     *
     * @return Font
     */
    public FontUIResource getControlTextFont()
    {
        return new FontUIResource(super.getControlTextFont().deriveFont(
            Font.PLAIN));
    }

    /**
     * Get menu text font - minus the usual bold.
     *
     * @return Font
     */
    public FontUIResource getMenuTextFont()
    {
        return new FontUIResource(super.getMenuTextFont().deriveFont(
            Font.PLAIN));
    }
}
