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

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XPathQueryHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

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

  public static boolean hasBDocTmPolicyId(Element signatureElement, XPathQueryHolder xPathQueryHolder) {
    Element policyIdentifier = DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_POLICY_IDENTIFIER);
    if (policyIdentifier != null) {
      final Element policyId = DomUtils.getElement(policyIdentifier, xPathQueryHolder.XPATH__POLICY_ID);
      if (policyId != null) {
        String policyIdString = Utils.trim(policyId.getTextContent());
        return Utils.areStringsEqualIgnoreCase(BDocTmSupport.BDOC_TM_POLICY_ID, policyIdString);
      }
    }
    return false;
  }

  public static String uriEncode(String string) {
    try {
      return URLEncoder.encode(string, "UTF-8")
          .replaceAll("\\+", "%20")
          .replaceAll("\\%21", "!")
          .replaceAll("\\%27", "'")
          .replaceAll("\\%28", "(")
          .replaceAll("\\%29", ")")
          .replaceAll("\\%7E", "~");
    } catch (UnsupportedEncodingException e) {
      LOG.error("Unable to decode '" + string + "' : " + e.getMessage(), e);
      return string;
    }
  }

  public static String fixEncoding(String string) {
    return string.replaceAll("\\+", "%2B");
  }
}

