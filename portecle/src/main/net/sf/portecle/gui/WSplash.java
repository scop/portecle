/*
 * WSplash.java
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

package net.sf.portecle.gui;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import java.lang.reflect.InvocationTargetException;

/**
 * Splash window that displays a supplied image for the requested time or
 * until the user clicks on it with their mouse.  Runs in a new thread
 * which can facilitate the calling application to initialise itself in
 * parallel.
 */
public class WSplash extends JWindow
{
    /** Contains the splash image */
    private JLabel m_jlSplash;

    /**
     * Creates a new Splash window and displays it for the specified period.
     *
     * @param splashImg The splash image
     * @param iDisplayMs Time in milli-seconds to display splash window
     */
    public WSplash(Image splashImg, int iDisplayMs)
    {
        initComponents(splashImg, iDisplayMs);
    }

    /**
     * Initialise the window's GUI components and display the splash window
     * for the specified period of time.
     *
     * @param splashImg The splash image
     * @param iDisplayMs Time in milli-seconds to display splash window
     */
    private void initComponents(Image splashImg, int iDisplayMs)
    {
        getContentPane().setLayout(new BorderLayout(0, 0));
        m_jlSplash = new JLabel(new ImageIcon(splashImg));
        getContentPane().add(m_jlSplash, BorderLayout.CENTER);

        pack();

        setLocationRelativeTo(null);

        addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e)
            {
                setVisible(false);
                dispose();
            }
        });

        final int iPauseMs = iDisplayMs;

        final Runnable closerRunner = new Runnable() {
            public void run()
            {
                setVisible(false);
                dispose();
            }
        };

        Runnable waitRunner = new Runnable() {
            public void run()
            {
                try
                {
                    Thread.sleep(iPauseMs);
                    SwingUtilities.invokeAndWait(closerRunner);
                }
                catch (InterruptedException e) { /* Ignore */ }
                catch (InvocationTargetException e) { /* Ignore */ }
            }
        };
        setVisible(true);
        toFront();
        Thread splashThread = new Thread(waitRunner, "SplashThread");
        splashThread.start();
    }
}
