/*
 * XmlFormatter.java
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

package net.sf.portecle.xml;

import java.util.StringTokenizer;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import org.xml.sax.*;

/**
 * Format an XML Document using indentation.
 */
public class XmlFormatter extends Object
{
    /** Quote character to use for strings */
    private static final char QUOTE = '\"';

    /** Tab string */
    private String m_sTab;

    /** Indentation level indicator */
    private int m_iLevel;

    /** Platform's newline string */
    private static final String PLATFORM_NEWLINE = System.getProperty("line.separator");

    /** "Neutral" newline string - compatible with copy/paste */
    private static final String NEUTRAL_NEWLINE = "\n";

    /** Newline string to use */
    private String m_sNewline;

    /**
     * Create a XmlFormatter that uses the tab character for indentation.
     *
     * @param bUsePlatformNewline True to use the platform's newline or false for the more neutral linefeed
     */
    public XmlFormatter(boolean bUsePlatformNewline)
    {
        setNewline(bUsePlatformNewline);

        m_sTab = "\t";
    }

    /**
     * Create an XmlFormatter that uses the space character for indentation.
     *
     * @param bUsePlatformNewline True to use the platform's newline or false for the more neutral linefeed
     * @param iTabLen Tab length
     */
    public XmlFormatter(boolean bUsePlatformNewline, int iTabLen)
    {
        setNewline(bUsePlatformNewline);

        StringBuffer sb = new StringBuffer(iTabLen);
        for (int iCnt=0; iCnt < iTabLen; iCnt++)
        {
            sb.append(' ');
        }
        m_sTab = sb.toString();
    }

    /**
     * Set newline character.
     *
     * @param bUsePlatformNewline True to use the platform's newline or false for the more neutral linefeed
     */
    private void setNewline(boolean bUsePlatformNewline)
    {
        if (bUsePlatformNewline)
        {
            m_sNewline = PLATFORM_NEWLINE;
        }
        else
        {
            m_sNewline = NEUTRAL_NEWLINE;
        }
    }

    /**
     * Format the supplied XML document.
     *
     * @param xml The XML document
     * @return The formatted XML document
     */
    public String format(Document xml)
    {
        return format(xml, null, null, null);
    }

    /**
     * Format the supplied XML document.
     *
     * @param xml The XML document
     * @param sXmlVersion XML version to embed in formatted XML
     * @return The formatted XML document
     */
    public String format(Document xml, String sXmlVersion)
    {
        return format(xml, sXmlVersion, null, null);
    }

    /**
     * Format the supplied XML document.
     *
     * @param xml The XML document
     * @param sXmlVersion XML version to embed in formatted XML
     * @param sEncoding Encoding to embed in formatted XML
     * @return The formatted XML document
     */
    public String format(Document xml, String sXmlVersion, String sEncoding)
    {
        return format(xml, sXmlVersion, sEncoding, null);
    }

    /**
     * Format the supplied XML document.
     *
     * @param xml The XML document
     * @param sXmlVersion XML version to embed in formatted XML
     * @param bStandalone Standalone XML?
     * @return The formatted XML document
     */
    public String format(Document xml, String sXmlVersion, Boolean bStandalone)
    {
        return format(xml, sXmlVersion, null, bStandalone);
    }

    /**
     * Format the supplied XML document.
     *
     * @param xml The XML document
     * @param sXmlVersion XML version to embed in formatted XML
     * @param sEncoding Encoding to embed in formatted XML
     * @param bStandalone Standalone XML?
     * @return The formatted XML document
     */
    public String format(Document xml, String sXmlVersion, String sEncoding, Boolean bStandalone)
    {
        // Initialise level indicator
        initialiseLevel();

        // Initialise buffer to hold the formatted XML
        StringBuffer sb = new StringBuffer(2048);

        // Format the XML declaration
        sb.append(formatXmlDecl(sXmlVersion, sEncoding, bStandalone));

        // Get root element
        Element root = xml.getDocumentElement();

        // Format elements before the root element
        sb.append(formatPreNodes(root));

        // Get the root element and format it and its children
        sb.append(formatElement(root));

        // Format elements after the root element
        sb.append(formatPostNodes(root));

        // Return formatted XML
        return sb.toString();
    }

    /**
     * Format the supplied node and any nodes before to it where the nodes are
     * of type comment, processing instruction or document type.
     *
     * @param node The node
     * @return The formatted nodes
     */
    private String formatPreNodes(Node node)
    {
        StringBuffer sb = new StringBuffer();

        Node previousNode = node.getPreviousSibling();

        if (previousNode != null)
        {
            sb.append(formatPreNodes(previousNode));

            switch (previousNode.getNodeType())
            {
                case Node.COMMENT_NODE :
                {
                    sb.append(formatComment((Comment)previousNode));
                    break;
                }
                case Node.PROCESSING_INSTRUCTION_NODE :
                {
                    sb.append(formatProcessingInstruction((ProcessingInstruction)previousNode));
                    break;
                }
                case Node.DOCUMENT_TYPE_NODE :
                {
                    sb.append(formatDocumentType((DocumentType)previousNode));
                    break;
                }
                default: break;
            }
        }

        return sb.toString();
    }

    /**
     * Format the supplied node and any nodes after to it where
     * the nodes are of type comment, processing instruction or
     * document type
     *
     * @param node The node
     * @return The formatted nodes
     */
    private String formatPostNodes(Node node)
    {
        StringBuffer sb = new StringBuffer();

        Node nextNode = node.getNextSibling();

        if (nextNode != null)
        {
            switch (nextNode.getNodeType())
            {
                case Node.COMMENT_NODE :
                {
                    sb.append(formatComment((Comment)nextNode));
                    break;
                }
                case Node.PROCESSING_INSTRUCTION_NODE :
                {
                    sb.append(formatProcessingInstruction((ProcessingInstruction)nextNode));
                    break;
                }
                case Node.DOCUMENT_TYPE_NODE :
                {
                    sb.append(formatDocumentType((DocumentType)nextNode));
                    break;
                }
                default: break;
            }
            sb.append(formatPostNodes(nextNode));
        }

        return sb.toString();
    }

    /**
     * Format the supplied XML declaration.
     *
     * @param sXmlVersion XML version to embed in declaration
     * @param sEncoding Encoding to embed in declaration, or null for none
     * @param bStandalone Standalone XML? Can be true for "yes", false for "no", or null to not include
     * @return The formatted XML declaration
     */
    private String formatXmlDecl(String sXmlVersion, String sEncoding, Boolean bStandalone)
    {
        StringBuffer sb = new StringBuffer();

        if (sXmlVersion != null)
        {
            sb.append("<?xml version=");
            sb.append(QUOTE);
            sb.append(sXmlVersion);
            sb.append(QUOTE);

            if (sEncoding != null)
            {
                sb.append(" encoding=");
                sb.append(QUOTE);
                sb.append(sEncoding);
                sb.append(QUOTE);
            }

            if (bStandalone != null)
            {
                sb.append(" standalone=");
                sb.append(QUOTE);
                if (bStandalone.booleanValue())
                {
                    sb.append("yes");
                }
                else
                {
                    sb.append("no");
                }
                sb.append(QUOTE);
            }

            sb.append("?>");
            sb.append(m_sNewline);
        }

        return sb.toString();
    }

    /**
     * Format the supplied element and its children.
     *
     * @param element The element
     * @return The formatted element
     */
    private String formatElement(Element element)
    {
        StringBuffer sb = new StringBuffer();

        incrementLevel(); // Increment level indicator

        String sIndent = getIndent(); // Get indent string for this level

        // Write out the common part of the element: '<tagname attr1="attr1" ... attrN="attrN"'
        String sName = element.getTagName();

        sb.append(sIndent);
        sb.append("<");
        sb.append(sName);

        String sAttributes = formatAttributes(element.getAttributes());

        if (sAttributes.length() > 0)
        {
            sb.append(" ");
            sb.append(sAttributes);
        }

        // Empty element so finish element tag with: '/>'
        if (emptyElement(element))
        {
            sb.append("/>");
            sb.append(m_sNewline);
        }
        // Non-empty element...
        else
        {
            sb.append(">"); // Finish opening element tag with: '>'

            // Get child nodes
            NodeList nl = element.getChildNodes();
            int iChildren = nl.getLength();

            boolean bFirstElement = true;

            // For each child node...
            for (int iCnt=0; iCnt < iChildren; iCnt++)
            {
                Node node = nl.item(iCnt);
                switch (node.getNodeType())
                {
                    // If the child node is a text node...
                    case Node.TEXT_NODE:
                    {
                        String sText = ((Text)node).getData().trim();

                        // Ignore white space text nodes
                        if (sText.length() == 0)
                        {
                            continue;
                        }
                        else
                        {
                            boolean bTextOnNewLine = false;

                            if ((sText.indexOf('\n') != -1) || (iChildren > 1))
                            {
                                bTextOnNewLine = true;

                                if (bFirstElement)
                                {
                                    sb.append(m_sNewline);
                                    bFirstElement = false;
                                }
                            }

                            sb.append(formatText(sText, bTextOnNewLine));
                        }
                        break;
                    }
                    // If the child node is an element node...
                    case Node.ELEMENT_NODE:
                    {
                        if (bFirstElement) // Need a newline as element contains other elements
                        {
                            sb.append(m_sNewline);
                            bFirstElement = false;
                        }

                        // Format the child element
                        sb.append(formatElement((Element)node));
                        break;
                    }
                    // If the child node is a comment node...
                    case Node.COMMENT_NODE:
                    {
                        if (bFirstElement) // Need a newline as element contains other elements
                        {
                            sb.append(m_sNewline);
                            bFirstElement = false;
                        }
                        sb.append(formatComment((Comment)node));
                        break;
                    }
                    // If the child node is a processing instruction...
                    case Node.PROCESSING_INSTRUCTION_NODE:
                    {
                        if (bFirstElement) // Need a newline as element contains other elements
                        {
                            sb.append(m_sNewline);
                            bFirstElement = false;
                        }
                        sb.append(formatProcessingInstruction((ProcessingInstruction)node));
                        break;
                    }
                    // If the child node is a CDATA section...
                    case Node.CDATA_SECTION_NODE:
                    {
                        if (bFirstElement) // Need a newline as element contains other elements
                        {
                            sb.append(m_sNewline);
                            bFirstElement = false;
                        }
                        sb.append(formatCdataSection((CDATASection)node));
                        break;
                    }
                    default: break;
                }

            }

            // Write out the closing element tag: '</tagname>'
            if (!((iChildren == 1) &&
                  (nl.item(0).getNodeType() == Node.TEXT_NODE) &&
                  (((Text)nl.item(0)).getData().trim().indexOf('\n') == -1)))
            {
                /* Need indentation if element contained other nodes (excluding a single text node
                   with no newlines) */
                sb.append(sIndent);
            }
            sb.append("</");
            sb.append(sName);
            sb.append(">");
            sb.append(m_sNewline);
        }

        decrementLevel(); // Decrement level indicator

        return sb.toString();
    }

    /**
     * Is the supplied element empty, ie does it contain no nodes
     * or only whitespace text nodes?
     *
     * @param element The element
     * @return True if the element is empty, false otherwise
     */
    private boolean emptyElement(Element element)
    {
        if (!element.hasChildNodes())
        {
            return true; // No nodes - empty
        }

        NodeList nl = element.getChildNodes();

        for (int iCnt=0; iCnt < nl.getLength(); iCnt++)
        {
            Node node = nl.item(iCnt);

            if (node.getNodeType() == Node.TEXT_NODE)
            {
                String sText = ((Text)node).getData().trim();

                if (sText.length() == 0)
                {
                    continue; // Whitespace text node - try next node
                }
            }
            return false; // Child node is not a whitespace text node
        }

        return true; // All child nodes are whitespace text nodes
    }

    /**
     * Format the text.
     *
     * @param sText The text
     * @param bOnNewLine I sthe text element on a new line?
     * @return The formatted text
     */
    private String formatText(String sText, boolean bOnNewLine)
    {
        StringBuffer sb = new StringBuffer();

        incrementLevel(); // Increment level indicator
        String sIndent = getIndent(); // Get indent string for this level

        // Write out text line-by-line
        StringTokenizer strTok = new StringTokenizer(sText, m_sNewline);

        while (strTok.hasMoreTokens())
        {
            String sLine = strTok.nextToken();
            sLine = sLine.trim();

            // Indent required?
            if (bOnNewLine)
            {
                sb.append(sIndent);
            }

            sb.append(escapeText(sLine));

            if (bOnNewLine)
            {
                sb.append(m_sNewline);
            }
        }

        decrementLevel(); // Decrement level indicator

        return sb.toString();
    }

    /**
     * Format the comment.
     *
     * @param comment The comment
     * @return The formatted comment
     */
    private String formatComment(Comment comment)
    {
        StringBuffer sb = new StringBuffer();

        incrementLevel(); // Increment level indicator

        String sIndent = getIndent(); // Get indent string for this level

        // Write out comment <!--...-->
        String sComment = comment.getData().trim();

        if (sComment.indexOf('\n') == -1)
        {
            // Comment all on one line
            sb.append(sIndent);
            sb.append("<!-- ");
            sb.append(sComment);
            sb.append(" -->");
            sb.append(m_sNewline);
        }
        else
        {
            // Comment on several lines
            sb.append(sIndent);
            sb.append("<!--");
            sb.append(m_sNewline);

            // Write out comment line-by-line
            StringTokenizer strTok = new StringTokenizer(sComment, m_sNewline);

            while (strTok.hasMoreTokens())
            {
                String sLine = strTok.nextToken();
                sLine = sLine.trim();

                sb.append(sIndent);
                sb.append("     ");
                sb.append(sLine);
                sb.append(m_sNewline);

            }

            sb.append(sIndent);
            sb.append("-->");
            sb.append(m_sNewline);
        }

        decrementLevel(); // Decrement level indicator

        return sb.toString();
    }

    /**
     * Format the processing instruction.
     *
     * @param processingInstruction The processing instruction
     * @return The formatted processing instruction
     */
    private String formatProcessingInstruction(ProcessingInstruction processingInstruction)
    {
        StringBuffer sb = new StringBuffer();

        incrementLevel(); // Increment level indicator

        String sIndent = getIndent(); // Get indent string for this level

        // Write out processing instruction <?target data?>
        sb.append(sIndent);
        sb.append("<?");
        sb.append(processingInstruction.getTarget());

        String sData = processingInstruction.getData().trim();

        // Is there data?
        if (sData.length() > 0)
        {
            if (sData.indexOf('\n') == -1)
            {
                // Data on one line
                sb.append(" ");
                sb.append(sData);
            }
            else
            {
                // Data on several lines
                sb.append(m_sNewline);

                // Write out data line-by-line
                StringTokenizer strTok = new StringTokenizer(sData, m_sNewline);

                while (strTok.hasMoreTokens())
                {
                    String sLine = strTok.nextToken();
                    sLine = sLine.trim();

                    sb.append(sIndent);
                    sb.append("  ");
                    sb.append(sLine);
                    sb.append(m_sNewline);
                }
                sb.append(sIndent);
            }
        }

        sb.append("?>");
        sb.append(m_sNewline);

        decrementLevel(); // Decrement level indicator

        return sb.toString();
    }

    /**
     * Format the CDATA section.
     *
     * @param cdataSection The CDATA section
     * @return The formatted CDATA section
     */
    private String formatCdataSection(CDATASection cdataSection)
    {
        StringBuffer sb = new StringBuffer();

        incrementLevel(); // Increment level indicator

        String sIndent = getIndent(); // Get indent string for this level

        // Write out comment <![CDATA[...]]>
        String sCDataSection = cdataSection.getData().trim();

        if (sCDataSection.indexOf('\n') == -1)
        {
            // CData all on one line
            sb.append(sIndent);
            sb.append("<![CDATA[");
            sb.append(sCDataSection);
            sb.append("]]>");
            sb.append(m_sNewline);
        }
        else
        {
            // CData on several lines
            sb.append(sIndent);
            sb.append("<![CDATA[");
            sb.append(m_sNewline);

            // Write out CData line-by-line
            StringTokenizer strTok = new StringTokenizer(sCDataSection, m_sNewline);

            while (strTok.hasMoreTokens())
            {
                String sLine = strTok.nextToken();
                sLine = sLine.trim();

                sb.append(sIndent);
                sb.append("  ");
                sb.append(sLine);
                sb.append(m_sNewline);

            }

            sb.append(sIndent);
            sb.append("]]>");
            sb.append(m_sNewline);
        }

        decrementLevel(); // Decrement level indicator

        return sb.toString();
    }

    /**
     * Format the document type.
     *
     * @param documentType The document type
     * @return The formatted Document Type
     */
    private String formatDocumentType(DocumentType documentType)
    {
        StringBuffer sb = new StringBuffer();

        incrementLevel(); // Increment level indicator

        // Write out the document type
        String sName = documentType.getName();
        String sPublicId = documentType.getPublicId();
        String sSystemId = documentType.getSystemId();

        sb.append("<!DOCTYPE ");
        sb.append(documentType.getName());

        if (sPublicId != null)
        {
            // <!DOCTYPE name PUBLIC "publicId" "systemId">
            sb.append(" PUBLIC ");
            sb.append(QUOTE);
            sb.append(escapeAttribute(sPublicId));
            sb.append(QUOTE);
            sb.append(' ');
        }
        else
        {
            // <!DOCTYPE name SYSTEM "systemId">
            sb.append(" SYSTEM ");
        }

        sb.append(QUOTE);
        sb.append(escapeAttribute(documentType.getSystemId()));
        sb.append(QUOTE);
        sb.append(">");
        sb.append(m_sNewline);

        decrementLevel(); // Decrement level indicator

        return sb.toString();
    }

    /**
     * Format the attributes.
     *
     * @param attributes The attributes
     * @return The formatted attributes
     */
    private String formatAttributes(NamedNodeMap attributes)
    {
        StringBuffer sb = new StringBuffer();

        int iLen = attributes.getLength();
        for (int iCnt=0; iCnt < iLen; iCnt++)
        {
            Attr attribute = (Attr)attributes.item(iCnt);

            sb.append(attribute.getName());
            sb.append("=");
            sb.append(QUOTE);
            sb.append(escapeAttribute(attribute.getValue()));
            sb.append(QUOTE);

            if (iCnt+1 < iLen)
            {
                sb.append(" ");
            }
        }
        return sb.toString();
    }

    /**
     * Escape any special characters in the supplied attribute.
     *
     * @param sAttribute The attribute
     * @return The escaped attribute
     */
    private String escapeAttribute(String sAttribute)
    {
        StringBuffer sb = new StringBuffer();

        int iLen = sAttribute.length();

        for (int iCnt=0; iCnt < iLen; iCnt++)
        {
            char chr = sAttribute.charAt(iCnt);

            if (chr == QUOTE)
            {
                sb.append("&quot;");
            }
            else if (chr == '<')
            {
                sb.append("&lt;");
            }
            else if (chr == '&')
            {
                sb.append("&amp;");
            }
            else
            {
                sb.append(chr);
            }
        }

        return sb.toString();
    }

    /**
     * Escape any special characters in the supplied text value.
     *
     * @param sText The text value
     * @return The escaped text value
     */
    private String escapeText(String sText)
    {
        StringBuffer sb = new StringBuffer();

        int iLen = sText.length();

        for (int iCnt=0; iCnt < iLen; iCnt++)
        {
            char chr = sText.charAt(iCnt);

            if (chr == '<')
            {
                sb.append("&lt;");
            }
            else if (chr == '&')
            {
                sb.append("&amp;");
            }
            else
            {
                sb.append(chr);
            }
        }

        return sb.toString();
    }

    /**
     * Initialise level indicator.
     */
    private void initialiseLevel()
    {
        m_iLevel = 0;
    }

    /**
     * Increment level indicator.
     */
    private void incrementLevel()
    {
        m_iLevel++;
    }

    /**
     * Decrement level indicator.
     */
    private void decrementLevel()
    {
        if (m_iLevel > 0)
        {
            m_iLevel--;
        }
    }

    /**
     * Get the value of the level indicator.
     *
     * @return The value of the level indicator
     */
    private int getLevel()
    {
        return m_iLevel;
    }

    /**
     * Get the indent string for the current level.
     *
     * @return The indent string
     */
    private String getIndent()
    {
        int iLevel = getLevel();

        StringBuffer sb = new StringBuffer(iLevel * m_sTab.length());

        for (int iCnt=1; iCnt < iLevel; iCnt++)
        {
            sb.append(m_sTab);
        }

        return sb.toString();
    }
}
