/*
 * DKeyStoreReport.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *             2004 Ville Skyttä, ville.skytta@iki.fi
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

package net.sf.portecle;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.MessageFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.Properties;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.ToolTipManager;
import javax.swing.border.EmptyBorder;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import net.sf.portecle.crypto.CryptoException;
import net.sf.portecle.crypto.DigestType;
import net.sf.portecle.crypto.DigestUtil;
import net.sf.portecle.crypto.KeyStoreType;
import net.sf.portecle.crypto.X509CertUtil;
import net.sf.portecle.gui.error.DThrowable;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Displays a report on the contents of a supplied KeyStore.
 */
class DKeyStoreReport
    extends JDialog
{
    /** Transformer factory for XML output */
    private static final TransformerFactory TF_FACTORY =
        TransformerFactory.newInstance();
    static {
        try {
            // XSLTC in J2SE 5 (why oh why doesn't it grok the "normal"
            // transformer properties... :()
            TF_FACTORY.setAttribute("indent-number", "2");
        }
        catch (IllegalArgumentException e) {
            // Ignore.
        }
    }

    /** Transformer properties for XML output */
    private static final Properties TF_PROPS = new Properties();
    static {
        try {
            TF_PROPS.load(DKeyStoreReport.class.getResourceAsStream(
                              "keystore-report-xml.properties"));
        } catch (java.io.IOException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /** Resource bundle */
    private static ResourceBundle m_res =
        ResourceBundle.getBundle("net/sf/portecle/resources");

    /** KeyStore report */
    private String m_sReport;

    /** KeyStore report in XML form */
    private String m_sReportXML;

    /** Panel to hold option controls */
    private JPanel m_jpOptions;

    /** Panel to hold report type controls */
    private JPanel m_jpReportType;

    /** Label for report type */
    private JLabel m_jlReportType;

    /** Panel to hold buttons */
    private JPanel m_jpButtons;

    /** Copy report button */
    private JButton m_jbCopy;

    /** Copy report as XMl button */
    private JButton m_jbCopyXml;

    /** OK button to dismiss dialog */
    private JButton m_jbOK;

    /** Panel to hold report */
    private JPanel m_jpReport;

    /** Tree to display report  */
    private JTree m_jtrReport;

    /** Scroll pane to place report in */
    private JScrollPane m_jspReport;

    /** Stores keystore to report on */
    private KeyStore m_keystore;

    /**
     * Creates new DKeyStoreReport dialog where the parent is a frame.
     *
     * @param parent Parent frame
     * @param bModal Is dialog modal?
     * @param keystore KeyStore to display report on
     * @throws CryptoException A crypto related problem was encountered
     * generating the KeyStore report
     * @throws ParserConfigurationException There was a serious problem
     * creating the XML report
     */
    public DKeyStoreReport(JFrame parent, boolean bModal, KeyStore keystore)
        throws CryptoException, ParserConfigurationException
    {
        super(parent, bModal);
        m_keystore = keystore;
        initComponents();
    }

    /**
     * Creates new DKeyStoreReport dialog where the parent is a dialog.
     *
     * @param parent Parent dialog
     * @param bModal Is dialog modal?
     * @param keystore KeyStore to display report on
     * @throws CryptoException A crypto related problem was encountered
     * generating the KeyStore report
     */
    public DKeyStoreReport(JDialog parent, boolean bModal, KeyStore keystore)
        throws CryptoException
    {
        super(parent, bModal);
        m_keystore = keystore;
        initComponents();
    }

    /**
     * Initialise the dialog's GUI components.
     *
     * @throws CryptoException A crypto related problem was encountered
     * generating the KeyStore report
     */
    private void initComponents() throws CryptoException
    {
        // Buttons
        m_jpButtons = new JPanel(new FlowLayout(FlowLayout.CENTER));

        m_jbOK = new JButton(m_res.getString("DKeyStoreReport.m_jbOK.text"));
        m_jbOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        m_jpButtons.add(m_jbOK);

        m_jbCopy = new JButton(
            m_res.getString("DKeyStoreReport.m_jbCopy.text"));
        m_jbCopy.setMnemonic(
            m_res.getString("DKeyStoreReport.m_jbCopy.mnemonic").charAt(0));
        m_jbCopy.setToolTipText(
            m_res.getString("DKeyStoreReport.m_jbCopy.tooltip"));
        m_jbCopy.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                copyPressed(false);
            }
        });

        m_jpButtons.add(m_jbCopy);

        m_jbCopyXml = new JButton(
            m_res.getString("DKeyStoreReport.m_jbCopyXml.text"));
        m_jbCopyXml.setMnemonic(
            m_res.getString("DKeyStoreReport.m_jbCopyXml.mnemonic").charAt(0));
        m_jbCopyXml.setToolTipText(
            m_res.getString("DKeyStoreReport.m_jbCopyXml.tooltip"));
        m_jbCopyXml.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                copyPressed(true);
            }
        });

        m_jpButtons.add(m_jbCopyXml);

        // KeyStore Report
        m_jpReport = new JPanel(new BorderLayout());
        m_jpReport.setBorder(new EmptyBorder(5, 5, 5, 5));

        // Load tree with KeyStore report
        m_jtrReport = new JTree(createReportNodes());
        // Top accomodate node icons with spare space (they are 16 pixels tall)
        m_jtrReport.setRowHeight(18);
        m_jtrReport.getSelectionModel().setSelectionMode(
            TreeSelectionModel.SINGLE_TREE_SELECTION);
        // Allow tooltips in tree
        ToolTipManager.sharedInstance().registerComponent(m_jtrReport);
        // Custom tree node renderer
        m_jtrReport.setCellRenderer(new ReportTreeCellRend());

        // Expand all nodes in tree
        TreeNode topNode = (TreeNode) m_jtrReport.getModel().getRoot();
        expandTree(m_jtrReport, new TreePath(topNode));

        m_jspReport = new JScrollPane(
            m_jtrReport,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
            JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        m_jspReport.setPreferredSize(new Dimension(350, 200));
        m_jpReport.add(m_jspReport, BorderLayout.CENTER);

        getContentPane().add(m_jpReport, BorderLayout.CENTER);
        getContentPane().add(m_jpButtons, BorderLayout.SOUTH);

        setTitle(m_res.getString("DKeyStoreReport.Title"));
        setResizable(true);

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                closeDialog();
            }
        });

        getRootPane().setDefaultButton(m_jbOK);

        pack();

        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                m_jbOK.requestFocus();
            }
        });
    }

    /**
     * Expand node and all sub-nodes in a JTree.
     *
     * @param tree The tree.
     * @param parent Path to node to expand
     */
    private void expandTree(JTree tree, TreePath parent)
    {
        // Traverse children expending nodes
        TreeNode node = (TreeNode) parent.getLastPathComponent();
        if (node.getChildCount() >= 0)
        {
            for (Enumeration en = node.children(); en.hasMoreElements();)
            {
                TreeNode subNode = (TreeNode) en.nextElement();
                TreePath path = parent.pathByAddingChild(subNode);
                expandTree(tree, path);
            }
        }

        tree.expandPath(parent);
    }

    /**
     * Copy the KeyStore report to the clipboard.
     *
     * @param bXml Copy as XML?
     */
    private void copyPressed(boolean bXml)
    {
        try
        {
            // Gte report...
            String sKeyStoreReport = null;

            if (!bXml)
            {
                // ...plain
                sKeyStoreReport = getKeyStoreReport();
            }
            else
            {
                // ...as XML
                sKeyStoreReport = getKeyStoreReportXml();
            }

            // Copy to clipboard
            Clipboard clipboard =
                Toolkit.getDefaultToolkit().getSystemClipboard();
            StringSelection copy = new StringSelection(sKeyStoreReport);
            clipboard.setContents(copy, copy);
        }
        catch (CryptoException ex)
        {
            DThrowable dThrowable = new DThrowable(this, true, ex);
            dThrowable.setLocationRelativeTo(this);
            dThrowable.setVisible(true);
        }
        catch (ParserConfigurationException ex)
        {
            DThrowable dThrowable = new DThrowable(this, true, ex);
            dThrowable.setLocationRelativeTo(this);
            dThrowable.setVisible(true);
        }
        catch (TransformerException ex)
        {
            DThrowable dThrowable = new DThrowable(this, true, ex);
            dThrowable.setLocationRelativeTo(this);
            dThrowable.setVisible(true);
        }
    }


    /**
     * Get the KeyStoreReport as XML.
     *
     * @return KeyStore report
     * @throws CryptoException A crypto related problem was encountered
     * generating the KeyStore report
     * @throws ParserConfigurationException There was a serious problem
     * creating the XML report
     * @throws TransformerException There was a serious problem
     * creating the XML report
     */
    private String getKeyStoreReportXml()
        throws CryptoException, ParserConfigurationException,
        TransformerException
    {
        StringWriter xml = new StringWriter();
        Transformer tr = TF_FACTORY.newTransformer();
        tr.setOutputProperties(TF_PROPS);
        tr.transform(new DOMSource(generateDocument()), new StreamResult(xml));
        return xml.toString();
    }


    /**
     * Get the KeyStoreReport as plain text.
     *
     * @return KeyStore report
     * @throws CryptoException A crypto related problem was encountered
     * generating the KeyStore report
     */
    private String getKeyStoreReport() throws CryptoException
    {
        try
        {
            // Buffer to hold report
            StringBuffer sbReport = new StringBuffer(2000);

            // General KeyStore information...

            // KeyStore type
            KeyStoreType ksType =
                KeyStoreType.getInstance(m_keystore.getType());
            sbReport.append(MessageFormat.format(
                                m_res.getString("DKeyStoreReport.report.type"),
                                new String[]{ksType.toString()}));
            sbReport.append("\n");

            // KeyStore provider
            sbReport.append(
                MessageFormat.format(
                    m_res.getString("DKeyStoreReport.report.provider"),
                    new String[]{m_keystore.getProvider().getName()}));
            sbReport.append("\n");

            // KeyStore size (entries)
            sbReport.append(
                MessageFormat.format(
                    m_res.getString("DKeyStoreReport.report.entries"),
                    new String[]{""+m_keystore.size()}));
            sbReport.append("\n\n");

            Enumeration aliases = m_keystore.aliases();

            // Get information on each KeyStore entry
            while (aliases.hasMoreElements())
            {
                // Alias
                String sAlias = (String) aliases.nextElement();
                sbReport.append(
                    MessageFormat.format(
                        m_res.getString("DKeyStoreReport.report.alias"),
                        new String[]{sAlias}));
                sbReport.append("\n");

                // Creation date

                if (ksType.supportsCreationDate())
                {
                    Date dCreation = m_keystore.getCreationDate(sAlias);

                    // Include timezone
                    String sCreation = DateFormat.getDateTimeInstance(
                        DateFormat.MEDIUM, DateFormat.LONG).format(dCreation);
                    sbReport.append(
                        MessageFormat.format(
                            m_res.getString("DKeyStoreReport.report.creation"),
                            new String[]{sCreation}));
                    sbReport.append("\n");
                }

                Certificate[] certChain = null;

                // Get entry type and certificates
                if (m_keystore.isKeyEntry(sAlias))
                {
                    certChain = m_keystore.getCertificateChain(sAlias);

                    if ((certChain == null) || (certChain.length == 0))
                    {
                        sbReport.append(
                            m_res.getString("DKeyStoreReport.report.key"));
                        sbReport.append("\n");
                    }
                    else
                    {
                        sbReport.append(
                            m_res.getString("DKeyStoreReport.report.keypair"));
                        sbReport.append("\n");
                    }
                }
                else
                {
                    sbReport.append(
                        m_res.getString("DKeyStoreReport.report.trustcert"));
                    sbReport.append("\n");

                    Certificate cert = m_keystore.getCertificate(sAlias);
                    if (cert != null)
                    {
                        certChain = new Certificate[]{cert};
                    }
                }

                // Get information on each certificate in an entry
                if ((certChain == null) || (certChain.length == 0))
                {
                    // Zero certificates
                    sbReport.append(
                        MessageFormat.format(
                            m_res.getString("DKeyStoreReport.report.certs"),
                            new String[]{""+0}));
                    sbReport.append("\n\n");
                }
                else
                {
                    X509Certificate[] x509CertChain =
                        X509CertUtil.convertCertificates(certChain);

                    // One or more certificates
                    int iChainLen = x509CertChain.length;
                    sbReport.append(
                        MessageFormat.format(
                            m_res.getString("DKeyStoreReport.report.certs"),
                            new String[]{""+iChainLen}));
                    sbReport.append("\n\n");

                    for (int iCnt=0; iCnt < iChainLen; iCnt++)
                    {
                        // Get information on an individual certificate
                        sbReport.append(
                            MessageFormat.format(
                                m_res.getString("DKeyStoreReport.report.cert"),
                                new String[]{""+(iCnt+1), ""+iChainLen}));
                        sbReport.append("\n");

                        X509Certificate x509Cert = x509CertChain[iCnt];

                        // Version
                        sbReport.append(
                            MessageFormat.format(
                                m_res.getString(
                                    "DKeyStoreReport.report.version"),
                                new String[]{""+x509Cert.getVersion()}));
                        sbReport.append("\n");

                        // Subject
                        sbReport.append(
                            MessageFormat.format(
                                m_res.getString(
                                    "DKeyStoreReport.report.subject"),
                                new Object[]{x509Cert.getSubjectDN()}));
                        sbReport.append("\n");

                        // Issuer
                        sbReport.append(
                            MessageFormat.format(
                                m_res.getString(
                                    "DKeyStoreReport.report.issuer"),
                                new Object[]{x509Cert.getIssuerDN()}));
                        sbReport.append("\n");

                        // Serial Number
                        String sSerialNumber = new BigInteger(
                            x509Cert.getSerialNumber().toByteArray())
                            .toString(16).toUpperCase();
                        sbReport.append(
                            MessageFormat.format(
                                m_res.getString(
                                    "DKeyStoreReport.report.serial"),
                                new String[]{sSerialNumber}));
                        sbReport.append("\n");

                        // Valid From
                        Date dValidFrom = x509Cert.getNotBefore();
                        String sValidFrom = DateFormat.getDateTimeInstance(
                            DateFormat.MEDIUM,
                            DateFormat.MEDIUM).format(dValidFrom);
                        sbReport.append(
                            MessageFormat.format(
                                m_res.getString(
                                    "DKeyStoreReport.report.validfrom"),
                                new String[]{sValidFrom}));
                        sbReport.append("\n");

                        // Valid Until
                        Date dValidTo = x509Cert.getNotAfter();
                        String sValidTo = DateFormat.getDateTimeInstance(
                            DateFormat.MEDIUM,
                            DateFormat.MEDIUM).format(dValidTo);
                        sbReport.append(
                            MessageFormat.format(
                                m_res.getString(
                                    "DKeyStoreReport.report.validuntil"),
                                new String[]{sValidTo}));
                        sbReport.append("\n");

                        // Public Key (algorithm and keysize)
                        int iKeySize =
                            X509CertUtil.getCertificateKeyLength(x509Cert);
                        String sKeyAlg =
                            x509Cert.getPublicKey().getAlgorithm();
                        sbReport.append(
                            MessageFormat.format(
                                m_res.getString(
                                    "DKeyStoreReport.report.pubkey"),
                                new String[]{sKeyAlg, ""+iKeySize}));
                        sbReport.append("\n");

                        // Signature Algorithm
                        sbReport.append(
                            MessageFormat.format(
                                m_res.getString(
                                    "DKeyStoreReport.report.sigalg"),
                                new String[]{x509Cert.getSigAlgName()}));
                        sbReport.append("\n");

                        byte[] bCert = x509Cert.getEncoded();

                        // MD5 Fingerprint
                        sbReport.append(
                            MessageFormat.format(
                                m_res.getString("DKeyStoreReport.report.md5"),
                                new String[]{DigestUtil.getMessageDigest(
                                                 bCert, DigestType.MD5)}));
                        sbReport.append("\n");

                        // SHA-1 Fingerprint
                        sbReport.append(
                            MessageFormat.format(
                                m_res.getString("DKeyStoreReport.report.sha1"),
                                new String[]{DigestUtil.getMessageDigest(
                                                 bCert, DigestType.SHA1)}));
                        sbReport.append("\n");

                        if (iCnt+1 < iChainLen)
                        {
                            sbReport.append("\n");
                        }
                    }

                    if (aliases.hasMoreElements())
                    {
                        sbReport.append("\n");
                    }
                }
            }

            // Return the report
            return sbReport.toString();
        }
        catch (GeneralSecurityException ex)
        {
            throw new CryptoException(
                m_res.getString(
                    "DKeyStoreReport.NoGenerateReport.exception.message"), ex);
        }
    }

    /**
     * Generate the KeyStore report as an XML Document.
     *
     * @return The KeyStiore report as an XML Document
     * @throws CryptoException A crypto related problem was encountered
     * generating the KeyStore report
     * @throws ParserConfigurationException There was a serious problem
     * creating the XML report
     */
    private Document generateDocument() throws
        CryptoException, ParserConfigurationException
    {
        try
        {
            // Create a new document object
            DocumentBuilderFactory docBuilderFactory =
                DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder =
                docBuilderFactory.newDocumentBuilder();
            Document xmlDoc = docBuilder.newDocument();

            // General KeyStore information
            KeyStoreType ksType =
                KeyStoreType.getInstance(m_keystore.getType());
            String sProvider = m_keystore.getProvider().getName();

            Element keystoreElement = xmlDoc.createElement("keystore");
            keystoreElement.setAttribute("type", ksType.toString());
            keystoreElement.setAttribute("provider", sProvider);
            xmlDoc.appendChild(keystoreElement);

            Enumeration aliases = m_keystore.aliases();

            // Get information on each KeyStore entry
            while (aliases.hasMoreElements())
            {
                String sAlias = (String) aliases.nextElement();

                String sCreation = null;
                if (ksType.supportsCreationDate()) {
                    Date dCreation = m_keystore.getCreationDate(sAlias);
                    sCreation = DateFormat.getDateTimeInstance(
                        DateFormat.MEDIUM,
                        DateFormat.MEDIUM).format(dCreation);
                }

                String sEntryType = null;
                Certificate[] certChain = null;

                // Get entry type and certificates
                if (m_keystore.isKeyEntry(sAlias))
                {
                    certChain = m_keystore.getCertificateChain(sAlias);

                    if ((certChain == null) || (certChain.length == 0))
                    {
                        sEntryType = "Key";
                    }
                    else
                    {
                        sEntryType = "KeyPair";
                    }
                }
                else
                {
                    sEntryType = "TrustedCertificate";
                    Certificate cert = m_keystore.getCertificate(sAlias);
                    if (cert != null)
                    {
                        certChain = new Certificate[]{cert};
                    }
                }

                Element entryElement = xmlDoc.createElement("entry");
                entryElement.setAttribute("alias", sAlias);

                if (sCreation != null)
                {
                    entryElement.setAttribute("creation_date", sCreation);
                }

                entryElement.setAttribute("type", sEntryType);
                keystoreElement.appendChild(entryElement);

                // Get information on each certificate in an entry
                if (certChain != null)
                {
                    X509Certificate[] x509CertChain =
                        X509CertUtil.convertCertificates(certChain);

                    int iChainLen = x509CertChain.length;

                    for (int iCnt=0; iCnt < iChainLen; iCnt++)
                    {
                        X509Certificate x509Cert = x509CertChain[iCnt];

                        Element certificateElement =
                            xmlDoc.createElement("certificate");
                        entryElement.appendChild(certificateElement);

                        // Get information on an individual certificate

                        // Version
                        Element versionNumberElement =
                            xmlDoc.createElement("version");
                        certificateElement.appendChild(versionNumberElement);
                        versionNumberElement.appendChild(
                            xmlDoc.createTextNode(""+x509Cert.getVersion()));

                        // Subject
                        Element subjectElement =
                            xmlDoc.createElement("subject");
                        certificateElement.appendChild(subjectElement);
                        subjectElement.appendChild(
                            xmlDoc.createTextNode(
                                x509Cert.getSubjectDN().toString()));

                        // Issuer
                        Element issuerElement = xmlDoc.createElement("issuer");
                        certificateElement.appendChild(issuerElement);
                        issuerElement.appendChild(
                            xmlDoc.createTextNode(
                                x509Cert.getIssuerDN().toString()));

                        // Serial Number
                        Element serialNumberElement =
                            xmlDoc.createElement("serial_number");
                        certificateElement.appendChild(serialNumberElement);
                        serialNumberElement.appendChild(
                            xmlDoc.createTextNode(
                                new BigInteger(
                                    x509Cert.getSerialNumber().toByteArray())
                                .toString(16).toUpperCase()));

                        // Valid From
                        Date dValidFrom = x509Cert.getNotBefore();
                        String sValidFrom = DateFormat.getDateTimeInstance(
                            DateFormat.MEDIUM,
                            DateFormat.MEDIUM).format(dValidFrom);

                        Element validFromElement =
                            xmlDoc.createElement("valid_from");
                        certificateElement.appendChild(validFromElement);
                        validFromElement.appendChild(
                            xmlDoc.createTextNode(sValidFrom));

                        // Valid Until
                        Date dValidTo = x509Cert.getNotAfter();
                        String sValidTo = DateFormat.getDateTimeInstance(
                            DateFormat.MEDIUM,
                            DateFormat.MEDIUM).format(dValidTo);

                        Element validUntilElement =
                            xmlDoc.createElement("valid_until");
                        certificateElement.appendChild(validUntilElement);
                        validUntilElement.appendChild(
                            xmlDoc.createTextNode(sValidTo));

                        // Public Key (algorithm and keysize)
                        int iKeySize =
                            X509CertUtil.getCertificateKeyLength(x509Cert);
                        String sKeyAlg =
                            x509Cert.getPublicKey().getAlgorithm();

                        Element publicKeyAlgElement =
                            xmlDoc.createElement("public_key_algorithm");
                        certificateElement.appendChild(publicKeyAlgElement);
                        publicKeyAlgElement.appendChild(
                            xmlDoc.createTextNode(
                                MessageFormat.format(
                                    "{0} ({1} bits)",
                                    new String[]{sKeyAlg, ""+iKeySize})));

                        // Signature Algorithm
                        Element signatureAlgElement =
                            xmlDoc.createElement("signature_algorithm");
                        certificateElement.appendChild(signatureAlgElement);
                        signatureAlgElement.appendChild(
                            xmlDoc.createTextNode(x509Cert.getSigAlgName()));

                        // Fingerprints
                        byte[] bCert = x509Cert.getEncoded();

                        Element md5FingerprintElement =
                            xmlDoc.createElement("md5_fingerprint");
                        certificateElement.appendChild(md5FingerprintElement);
                        md5FingerprintElement.appendChild(
                            xmlDoc.createTextNode(
                                DigestUtil.getMessageDigest(
                                    bCert, DigestType.MD5)));

                        Element sha1FingerprintElement =
                            xmlDoc.createElement("sha1_fingerprint");
                        certificateElement.appendChild(sha1FingerprintElement);
                        sha1FingerprintElement.appendChild(
                            xmlDoc.createTextNode(
                                DigestUtil.getMessageDigest(
                                    bCert, DigestType.SHA1)));
                    }
                }
            }

            return xmlDoc;
        }
        catch (GeneralSecurityException ex)
        {
            throw new CryptoException(
                m_res.getString(
                    "DKeyStoreReport.NoGenerateReport.exception.message"), ex);
        }
    }

    /**
     * Create tree node with KeyStore report.
     *
     * @throws CryptoException A crypto related problem was encountered
     * creating the tree node
     * @return The tree node
     */
    private DefaultMutableTreeNode createReportNodes() throws CryptoException
    {
        try
        {
            // KeyStore type
            KeyStoreType ksType =
                KeyStoreType.getInstance(m_keystore.getType());

            // KeyStore provider
            String sProvider = m_keystore.getProvider().getName();

            // Top node
            DefaultMutableTreeNode topNode = new DefaultMutableTreeNode(
                MessageFormat.format(
                    m_res.getString("DKeyStoreReport.TopNodeName"),
                    new String[]{ksType.toString(), sProvider}));

            // One sub-node per entry
            Enumeration aliases = m_keystore.aliases();

            // Get information on each KeyStore entry
            while (aliases.hasMoreElements())
            {
                // Entry alias
                String sAlias = (String) aliases.nextElement();

                Certificate[] certChain = null;
                DefaultMutableTreeNode entryNode = null;

                // Entry type
                if (m_keystore.isKeyEntry(sAlias))
                {
                    certChain = m_keystore.getCertificateChain(sAlias);

                    if ((certChain == null) || (certChain.length == 0))
                    {
                        entryNode = new DefaultMutableTreeNode(
                            ReportTreeCellRend.Entry.getKeyInstance(sAlias));
                    }
                    else
                    {
                        entryNode = new DefaultMutableTreeNode(
                            ReportTreeCellRend.Entry.getKeyPairInstance(
                                sAlias));
                    }
                }
                else
                {
                    entryNode = new DefaultMutableTreeNode(
                        ReportTreeCellRend.Entry.getTrustedCertificateInstance(
                            sAlias));

                    Certificate cert = m_keystore.getCertificate(sAlias);
                    if (cert != null)
                    {
                        certChain = new Certificate[]{cert};
                    }
                }

                topNode.add(entryNode);

                // Creation date, if applicable
                if (ksType.supportsCreationDate())
                {
                    Date dCreation = m_keystore.getCreationDate(sAlias);
                    String sCreation = DateFormat.getDateTimeInstance(
                        DateFormat.MEDIUM,
                        DateFormat.MEDIUM).format(dCreation);
                    entryNode.add(new DefaultMutableTreeNode(sCreation));
                }

                // One or more certificates?
                if (certChain != null && certChain.length != 0)
                {
                    DefaultMutableTreeNode certsNode =
                        new DefaultMutableTreeNode(
                            m_res.getString("DKeyStoreReport.Certificates"));
                    entryNode.add(certsNode);

                    // Get information on each certificate in entry
                    X509Certificate[] x509CertChain =
                        X509CertUtil.convertCertificates(certChain);

                    int iChainLen = x509CertChain.length;

                    for (int iCnt=0; iCnt < iChainLen; iCnt++)
                    {
                        DefaultMutableTreeNode certNode =
                            new DefaultMutableTreeNode(
                                MessageFormat.format(
                                    m_res.getString(
                                        "DKeyStoreReport.Certificate"),
                                    new String[]{""+(iCnt+1), ""+iChainLen}));
                        certsNode.add(certNode);

                        X509Certificate x509Cert = x509CertChain[iCnt];

                        // Version
                        certNode.add(new DefaultMutableTreeNode(
                                         ""+x509Cert.getVersion()));

                        // Subject
                        certNode.add(new DefaultMutableTreeNode(
                                         x509Cert.getSubjectDN()));

                        // Issuer
                        certNode.add(new DefaultMutableTreeNode(
                                         x509Cert.getIssuerDN()));

                        // Serial Number
                        String sSerialNumber = new BigInteger(
                            x509Cert.getSerialNumber().toByteArray())
                            .toString(16).toUpperCase();
                        certNode.add(
                            new DefaultMutableTreeNode(sSerialNumber));

                        // Valid From
                        Date dValidFrom = x509Cert.getNotBefore();
                        String sValidFrom = DateFormat.getDateTimeInstance(
                            DateFormat.MEDIUM,
                            DateFormat.MEDIUM).format(dValidFrom);
                        certNode.add(new DefaultMutableTreeNode(sValidFrom));

                        // Valid Until
                        Date dValidTo = x509Cert.getNotAfter();
                        String sValidTo = DateFormat.getDateTimeInstance(
                            DateFormat.MEDIUM,
                            DateFormat.MEDIUM).format(dValidTo);
                        certNode.add(new DefaultMutableTreeNode(sValidTo));

                        // Public Key (algorithm and keysize)
                        int iKeySize =
                            X509CertUtil.getCertificateKeyLength(x509Cert);
                        String sKeyAlg =
                            x509Cert.getPublicKey().getAlgorithm();
                        certNode.add(
                            new DefaultMutableTreeNode(
                                MessageFormat.format(
                                    m_res.getString("DKeyStoreReport.KeyAlg"),
                                    new String[]{sKeyAlg, ""+iKeySize})));

                        // Signature Algorithm
                        certNode.add(new DefaultMutableTreeNode(
                                         x509Cert.getSigAlgName()));

                        byte[] bCert = x509Cert.getEncoded();

                        // MD5 Fingerprint
                        certNode.add(new DefaultMutableTreeNode(
                                         DigestUtil.getMessageDigest(
                                             bCert, DigestType.MD5)));

                        // SHA-1 Fingerprint
                        certNode.add(new DefaultMutableTreeNode(
                                         DigestUtil.getMessageDigest(
                                             bCert, DigestType.SHA1)));
                    }
                }
            }

            return topNode;
        }
        catch (GeneralSecurityException ex)
        {
            throw new CryptoException(
                m_res.getString(
                    "DKeyStoreReport.NoGenerateReport.exception.message"), ex);
        }
    }

    /**
     * OK button pressed or otherwise activated.
     */
    private void okPressed()
    {
        closeDialog();
    }

    /**
     * Hides the Report dialog.
     */
    private void closeDialog()
    {
        setVisible(false);
        dispose();
    }
}
