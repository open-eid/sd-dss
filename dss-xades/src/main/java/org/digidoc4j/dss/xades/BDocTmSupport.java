/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.digidoc4j.dss.xades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.xades.definition.XAdESPath;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

/**
 * Support for BDoc TM profile signatures
 */
public class BDocTmSupport implements Serializable {

  private static final Logger LOG = LoggerFactory.getLogger(BDocTmSupport.class);
  public static final String BDOC_TM_POLICY_ID = "urn:oid:1.3.6.1.4.1.10015.1000.3.2.1";
  public static final String BDOC_TM_POLICY_QUALIFIER = "OIDAsURN";

  public static boolean isBdocTmSignatureProfile(XAdESSignatureParameters params) {
    Policy signaturePolicy = params.bLevel().getSignaturePolicy();
    if(signaturePolicy == null) {
      return false;
    }
    String policyId = Utils.trim(signaturePolicy.getId());
    return BDOC_TM_POLICY_ID.equals(policyId);
  }

  public static boolean hasBDocTmPolicyId(Element signatureElement, XAdESPath xadesPath) {

    Element policyIdentifier = DomUtils.getElement(signatureElement, xadesPath.getSignaturePolicyIdentifierPath());
    if (policyIdentifier != null) {
      final Element policyId = DomUtils.getElement(policyIdentifier, xadesPath.getCurrentSignaturePolicyId());
      if (policyId != null) {
        String policyIdString = Utils.trim(policyId.getTextContent());
        return Utils.areStringsEqualIgnoreCase(BDocTmSupport.BDOC_TM_POLICY_ID, policyIdString);
      }
    }
    return false;
  }

  public static boolean hasBDocTmOcsp(Element signatureElement, XAdESPath xadesPath) {
    if (hasBDocTmPolicyId(signatureElement, xadesPath)) {
      String ocspValuesPath = xadesPath.getRevocationValuesPath() + xadesPath.getCurrentOCSPValuesChildren().substring(1);
      NodeList ocspValues = DomUtils.getNodeList(signatureElement, ocspValuesPath);
      for (int i = 0; i < ocspValues.getLength(); i++) {
        try {
          Element element = (Element) ocspValues.item(i);
          byte[] binaries = getEncapsulatedTokenBinaries(element);
          BasicOCSPResp basicOCSPResp = DSSRevocationUtils.loadOCSPFromBinaries(binaries);
          Extension ocspNonce = basicOCSPResp.getExtension(new ASN1ObjectIdentifier(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId()));
          if (ocspNonce != null && isOcspNonceInValidFormat(ocspNonce)) {
            //BDoc-TM has policy id and OCSP response containing TimeMark
            return true;
          }
        } catch (Exception e) {
          String errorMessage = "Unable to parse OCSP response binaries : {}";
          if (LOG.isDebugEnabled()) {
            LOG.error(errorMessage, e.getMessage(), e);
          } else {
            LOG.warn(errorMessage, e.getMessage());
          }
        }
      }
    }
    return false;
  }

  private static byte[] getEncapsulatedTokenBinaries(Element encapsulatedElement) {
    if (encapsulatedElement.hasChildNodes()) {
      Node firstChild = encapsulatedElement.getFirstChild();
      if (Node.TEXT_NODE == firstChild.getNodeType()) {
        String base64String = firstChild.getTextContent();
        if (Utils.isBase64Encoded(base64String)) {
          return Utils.fromBase64(base64String);
        }
      }
    }
    throw new DSSException(String.format("Cannot create the token reference. "
            + "The element with local name [%s] must contain an encapsulated base64 token value!", encapsulatedElement.getLocalName()));
  }

  private static boolean isOcspNonceInValidFormat(Extension extension) {
    try {
      ASN1OctetString ev = extension.getExtnValue();
      byte[] octets = ev.getOctets();
      DigestAlgorithm usedDigestAlgorithm = getExtensionDigestAlgorithm(octets);
      ASN1Sequence seq = ASN1Sequence.getInstance(octets);
      byte[] foundHash = ((DEROctetString) seq.getObjectAt(1)).getOctets();
      return usedDigestAlgorithm.getSaltLength() == foundHash.length;
    } catch (Exception e) {
      return false;
    }
  }

  private static DigestAlgorithm getExtensionDigestAlgorithm(byte[] octets) {
    ASN1Encodable oid = ASN1Sequence.getInstance(octets).getObjectAt(0);
    String oidString = ((DLSequence) oid).getObjects().nextElement().toString();
    return DigestAlgorithm.forOID(oidString);
  }

  public static String uriEncode(String string) {
    try {
      return URLEncoder.encode(string, "UTF-8")
          .replaceAll("\\+", "%20")
          .replaceAll("\\%7E", "~"); // by https://www.urlencoder.org/
    } catch (UnsupportedEncodingException e) {
      LOG.error("Unable to decode '" + string + "' : " + e.getMessage(), e);
      return string;
    }
  }

  public static String fixEncoding(String string) {
    return string.replaceAll("\\+", "%2B");
  }
}

