=-=-=-=-=-=-=-=-=
 Portecle README
=-=-=-=-=-=-=-=-=

Portecle is a user friendly GUI application for creating, managing and
examining keystores, keys, certificates, certificate requests,
certificate revocation lists and more.

Currently, Portecle can be used to, for example:

* Create, load, save, and convert keystores.
* Generate DSA and RSA key pair entries with self-signed version 1
  X.509 certificates.
* Import X.509 certificate files as trusted certificates.
* Import key pairs from PKCS #12 files.
* Clone and change the password of key pair entries and keystores.
* View the details of certificates contained within keystore entries,
  certificate files, and SSL/TLS connections.
* Export keystore entries in a variety of formats.
* Generate and view certification requests (CSRs).
* Import Certificate Authority (CA) replies.
* Change the password of key pair entries and keystores.
* Delete, clone, and rename keystore entries.
* View the details of certificate revocation list (CRL) files.

Getting up and running with Portecle is quick and easy.  Everything
you need to know is detailed below.  Being written in Java, Portecle
will run on any machine that has a suitable Java runtime environment
installed.  Note that a prerequisite is that you must have Java SE 6
or later on your machine.  The latest version of the Java SE is
available from http://www.oracle.com/technetwork/java/index.html

You can access the online help of Portecle from within the Portecle
GUI, or on the Internet at http://portecle.sourceforge.net/#docs

1 Installing
------------

The default binary distribution of Portecle contains everything you'll
need to run Portecle with Java SE 6 or later (except Java SE itself,
see above).  The easiest way to install it is to unzip the Portecle
binary distribution to a directory somewhere on your filesystem.

The binary distribution contains the Portecle jar file (portecle.jar)
as well as Bouncy Castle provider jar (bcprov.jar) for Java SE 6.
If you wish to run Portecle with a later Java version, or update the
bundled Bouncy Castle provider for some other reason, simply download
an update for your version of Java from http://www.bouncycastle.org/
and place it into the same directory as portecle.jar with the name
bcprov.jar, overwriting the existing one already there (if any).  The
binary distribution also contains icons for use with Portecle
(portecle.ico, portecle.png).

Portecle can additionally use the GNU Classpath (version 0.90 or later)
security providers if they are installed.  Support for GNU Keyring (GKR)
keystores requires these providers.  For more information about GNU
Classpath, see http://www.gnu.org/software/classpath/

Depending on your Portecle usage patterns, the Bouncy Castle provider
may require the JCE unlimited strength jurisdiction policy files
installed to function properly.  See "IMPORTANT NOTES" at
http://www.bouncycastle.org/documentation.html .  Failures related
to lack of these policy files usually manifest themselves as errors
loading keystores with an error message like "Unsupported keysize or
algorithm parameters" or "Illegal key size" when trying to import keys.

The default way of running Portecle uses the "java -jar" method, which
means that the Class-Path defined in portecle.jar's MANIFEST.MF will
be used to locate all classes.  You can also invoke Portecle by its
"main" class, net.sf.portecle.FPortecle.  This method allows you to
use a Bouncy Castle provider jar elsewhere on your filesystem.

The following chapters contain examples how to run Portecle; all of
the examples assume that the JRE/JRE "bin" directory has been added to
your PATH environment variable.

1.1 Windows Command Line
------------------------

Assuming you have an appropriate JRE/JDK installed and have placed the
Portecle and Bouncy Castle provider JAR files into a directory
c:\java you can run Portecle like so:

  java -jar c:\java\portecle.jar

In most setups, if portecle.jar and bcprov.jar were installed as
instructed above, Portecle can also be run by double-clicking
portecle.jar in the Windows Explorer.

If you wish to use a Bouncy Castle provider somewhere else on your
filesystem, for example c:\java\bcprov-jdk16-140.jar, use:

  java -cp c:\java\portecle.jar;c:\java\bcprov-jdk16-140.jar
       net.sf.portecle.FPortecle

Note that the above command should be on one line; it has been line
wrapped here for readability.

1.2 UNIX Command Line
---------------------

Assuming you have an appropriate JRE/JDK installed and have placed the
Portecle and Bouncy Castle provider jar files into a directory
/usr/share/java you can run Portecle like so:

  java -jar /usr/share/java/portecle.jar

If you wish to use a Bouncy Castle provider somewhere else on your
filesystem, for example /usr/share/java/bcprov-jdk16-140.jar, use:

  java -cp /usr/share/java/portecle.jar:/usr/share/java/bcprov-jdk16-140.jar \
       net.sf.portecle.FPortecle

Note that the above command should be on one line; it has been line
wrapped here for readability.

1.3 Experimental Features
-------------------------

Portecle releases may contain experimental features that are not
enabled by default.  These have known limitations or incomplete
implementations that make them unsuitable for production use, but they
may be valuable for early adopters.  To enable these features, use
"-Dportecle.experimental=true" in your Portecle invocation command
line.  See the file NEWS for information about status of current
experimental features.

2 Copyright and License
-----------------------

Copyright © 2004 Wayne Grant
            2004 Mark Majczyk
            2004-2011 Ville Skyttä

Portecle is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.

Portecle is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with Portecle, see the file LICENSE.txt; if not, write to the
Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
MA 02110-1301 USA

3 Contact
---------

For contact information, mailing lists and issue tracking facilities,
see Portecle's SourceForge.net project page at
http://sourceforge.net/projects/portecle/
