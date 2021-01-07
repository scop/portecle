# Portecle [![CI status](https://github.com/scop/portecle/workflows/CI/badge.svg)](https://github.com/scop/portecle/actions?query=workflow%3ACI) [![Download](https://img.shields.io/sourceforge/dt/portecle.svg)](https://sourceforge.net/projects/portecle/files/latest/download)

Portecle is a user friendly GUI application for creating, managing and
examining keystores, keys, certificates, certificate requests,
certificate revocation lists and more.

Currently, Portecle can be used to, for example:

- Create, load, save, and convert keystores.
- Generate DSA and RSA key pair entries with self-signed X.509
  certificates.
- Import X.509 certificate files as trusted certificates.
- Import key pairs from PKCS #12 files.
- Clone and change the password of key pair entries and keystores.
- View the details of certificates contained within keystore entries,
  certificate files, and SSL/TLS connections.
- Export keystore entries in a variety of formats.
- Generate and view certification requests (CSRs).
- Import Certificate Authority (CA) replies.
- Change the password of key pair entries and keystores.
- Delete, clone, and rename keystore entries.
- View the details of certificate revocation list (CRL) files.

Getting up and running with Portecle is quick and easy.  Everything
you need to know is detailed below. Being written in Java, Portecle
will run on any machine that has a suitable Java runtime environment
installed. 

You can access the online help of Portecle from within the Portecle
GUI, or online at http://portecle.sourceforge.net/#docs

## Installing

First, you'll need a suitable Java runtime environment installed.
Java SE version 7 or later is required; see for example
https://www.oracle.com/technetwork/java/index.html and
https://openjdk.java.net/ for available versions and install
instructions.

Apart from Java, the default binary distribution of Portecle contains
everything you'll need to run it. The easiest way to install it is to
unzip the binary distribution to a directory somewhere on your
filesystem.

The binary distribution contains the Portecle jar file
(`portecle.jar`) as well as Bouncy Castle provider and PKIX jars
(`bcprov.jar`, `bcpkix.jar`) for Java SE 7.  If you wish to run
Portecle with a later Java version, or update the bundled Bouncy
Castle jars for some other reason, simply download an update for your
version of Java from https://www.bouncycastle.org/ and place the jars
into the same directory as `portecle.jar` with the names `bcprov.jar`
and `bcpkix.jar`, overwriting the existing one already there (if any).
The binary distribution also contains icons for use with Portecle.

Portecle can additionally use the GNU Classpath (version 0.90 or
later) security providers if they are installed. Support for GNU
Keyring (GKR) keystores requires these providers. For more
information about GNU Classpath, see
https://www.gnu.org/software/classpath/

Depending on your Portecle usage patterns, the Bouncy Castle provider
may require the JCE unlimited strength jurisdiction policy files
installed to function properly.  See "IMPORTANT NOTES" at
https://www.bouncycastle.org/documentation.html. Failures related to
lack of these policy files usually manifest themselves as errors
loading keystores with an error message like "Unsupported keysize or
algorithm parameters" or "Illegal key size" when trying to import
keys.

The default way of running Portecle uses the `java -jar` method, which
means that the `Class-Path` defined in `portecle.jar`'s `MANIFEST.MF`
will be used to locate all classes. You can also invoke Portecle by
its "main" class, `net.sf.portecle.FPortecle`. This method allows you
to use a Bouncy Castle provider jar elsewhere on your filesystem.

The following chapters contain examples how to run Portecle; all of
the examples assume that the JRE/JDK `bin` directory has been added to
your `PATH` environment variable.

### Windows Command Line

Assuming you have an appropriate JRE/JDK installed and have placed the
Portecle and Bouncy Castle provider JAR files into a directory
`c:\java` you can run Portecle like so:

```
java -jar c:\java\portecle.jar
```

In most setups, if `portecle.jar`, `bcprov.jar`, and `bcpkix.jar` were
installed as instructed above, Portecle can also be run by
double-clicking `portecle.jar` in the Windows Explorer.

If you wish to manage the jar locations yourself, use Java's `-cp`
option for that, and `net.sf.portecle.FPortecle` as the class to
launch.

### UNIX Command Line

Assuming you have an appropriate JRE/JDK installed and have placed the
Portecle and Bouncy Castle provider jar files into a directory
`/usr/share/java` you can run Portecle like so:

```
java -jar /usr/share/java/portecle.jar
```

If you wish to manage the jar locations yourself, use Java's `-cp`
option for that, and `net.sf.portecle.FPortecle` as the class to
launch.

### macOS Application Bundle

As of v1.11 a macOS application bundle is available and provides an
alternative way to run Portecle on your Mac. Unzip `portecle.app.zip` and
CTRL-Right-Click on the extracted Portecle.app bundle. macOS will warn you 
about the fact that the bundle is not signed but allows you to run it
anyway (this procedure is only required the first time you run Protecle). 

### Experimental Features

Portecle releases may contain experimental features that are not
enabled by default.  These have known limitations or incomplete
implementations that make them unsuitable for production use, but they
may be valuable for early adopters. To enable these features, use
`-Dportecle.experimental=true` in your Portecle invocation command
line. See the file [NEWS.txt](NEWS.txt) for information about status
of current experimental features.

## Copyright and License

Copyright © 2004 Wayne Grant, 2004 Mark Majczyk, 2004-2019 Ville Skyttä

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

## Contact

For contact information and issue tracking facilities,
see Portecle's project pages at:
- https://github.com/scop/portecle
- https://sourceforge.net/projects/portecle/
