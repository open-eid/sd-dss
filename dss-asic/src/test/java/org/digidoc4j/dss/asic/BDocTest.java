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
package org.digidoc4j.dss.asic;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.asic.signature.asice.ASiCELevelLTTest;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XPathQueryHolder;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.apache.commons.lang.StringUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.IOException;
import java.util.List;
import java.util.zip.ZipFile;

import static eu.europa.esig.dss.DigestAlgorithm.SHA256;
import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class BDocTest extends ASiCELevelLTTest {

    private static final String TM_POLICY = "urn:oid:1.3.6.1.4.1.10015.1000.3.2.1";
    private static final String OIDAS_URN = "OIDAsURN";

    private DSSDocument documentToSign;

    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();

    @Before
    public void setUp() throws Exception {
        documentToSign = new InMemoryDocument("Hello Wolrd !".getBytes(), "test.text");
    }

    @Test
    public void bdocShouldContainManifest() throws Exception {
        documentToSign = sign();
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(documentToSign);
        Assert.assertTrue("BDoc does not contain META-INF/manifest.xml", containsManifest(validator));
    }

    @Test
    public void signingTwiceShouldNotCreateConflictingManifest() throws Exception {
        documentToSign = sign();
        getSignatureParameters().aSiC().setSignatureFileName("signatures002.xml");
        documentToSign = sign();
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(documentToSign);
        Assert.assertTrue("BDoc does not contain META-INF/manifest.xml", containsManifest(validator));
    }

    @Test
    public void settingSignatureIdWhenSigningAsic() throws Exception {
        getSignatureParameters().setDeterministicId("SIGNATURE-1");
        documentToSign = sign();
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(documentToSign);
        assertEquals("SIGNATURE-1", validator.getSignatures().get(0).getId());
    }

    @Test
    public void signatureReferences_ShouldUseUriEncoding() throws Exception {
        documentToSign = new InMemoryDocument("Hello Wolrd !".getBytes(), "dds_JÜRIÖÖ € žŠ päev.txt");
        getSignatureParameters().setDetachedContent(documentToSign);
        documentToSign = sign();
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(documentToSign);
        XAdESSignature signature = (XAdESSignature)validator.getSignatures().get(0);
        String referenceUri = getSignedDataFileReferenceUri(signature);
        assertEquals("dds_J%C3%9CRI%C3%96%C3%96%20%E2%82%AC%20%C5%BE%C5%A0%20p%C3%A4ev.txt", referenceUri);
    }

    @Test
    public void bdocTM_shouldNotContainTimestamp() throws Exception {
        XAdESSignature xAdESSignature = createXadesSignatureForBdocTm();
        assertTrue(isTimestampEmpty(xAdESSignature));
    }

    @Test
    public void bdocTM_shouldNotContainTimestamp_whenPolicyIdContainsWhitespaceCharacters() throws Exception {
        addSignaturePolicy("\n urn:oid:1.3.6.1.4.1.10015.1000.3.2.1\t \n");
        DSSDocument signedDocument = sign();
        XAdESSignature xAdESSignature =  extractXadesSignature(signedDocument);
        assertTrue(isTimestampEmpty(xAdESSignature));
    }

    @Test
    public void bdocTM_shouldContainPolicyId() throws Exception {
        XAdESSignature xAdESSignature = createXadesSignatureForBdocTm();
        SignaturePolicy policy = xAdESSignature.getPolicyId();
        String policyIdentifier = policy.getIdentifier().trim();
        assertEquals(TM_POLICY, policyIdentifier);
        assertTrue(StringUtils.isNotBlank(policy.getUrl()));
    }

    @Test
    public void bdocTM_shoudlContainPolicyQualifier() throws Exception {
        XAdESSignature xAdESSignature = createXadesSignatureForBdocTm();
        String qualifier = getSignaturePolicyQualifier(xAdESSignature);
        assertEquals(OIDAS_URN, qualifier);
    }

    @Test
    public void setSignatureId_whenCreatingXadesSignature() throws Exception {
        getSignatureParameters().setDeterministicId("SIGNATURE-1");
        XAdESSignature signature = createXadesSignatureForBdocTm();
        assertEquals("SIGNATURE-1", signature.getId());
    }

    @Test
    public void bdocShouldContainZipComment() throws Exception {
        getSignatureParameters().aSiC().setZipComment(true);
        getSignatureParameters().aSiC().setZipCommentValue("My name is Maximus Decimus Meridius");
        DSSDocument signedDocument = sign();
        String containerPath = testFolder.newFile().getPath();
        signedDocument.save(containerPath);
        ZipFile zipFile = new ZipFile(containerPath);
        assertEquals("My name is Maximus Decimus Meridius", zipFile.getComment());
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    public void signAndVerify() throws IOException {
        //DO nothing
    }

    private boolean containsManifest(SignedDocumentValidator validator) {
        List<DSSDocument> detachedContents = validator.getDetachedContents();
        for (DSSDocument dssDocument : detachedContents) {
            if ("META-INF/manifest.xml".equals(dssDocument.getName())) {
                return true;
            }
        }
        return false;
    }

    private String getSignedDataFileReferenceUri(XAdESSignature xAdESSignature) {
        XPathQueryHolder xPathQueryHolder = xAdESSignature.getXPathQueryHolder();
        Element signatureElement = xAdESSignature.getSignatureElement();
        NodeList references = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_REFERENCE);
        Node dataFileReference = references.item(0);
        String uri = dataFileReference.getAttributes().getNamedItem("URI").getNodeValue();
        return uri;
    }

    private XAdESSignature createXadesSignatureForBdocTm() {
        addTmSignaturePolicy();
        DSSDocument signedDocument = sign();
        return extractXadesSignature(signedDocument);
    }

    private XAdESSignature extractXadesSignature(DSSDocument signedDocument) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        List<AdvancedSignature> signatureList = validator.getSignatures();
        return (XAdESSignature)signatureList.get(0);
    }

    private void addTmSignaturePolicy() {
        addSignaturePolicy(TM_POLICY);
    }

    private void addSignaturePolicy(String policyId) {
        Policy signaturePolicy = new Policy();
        signaturePolicy.setId(policyId);
        signaturePolicy.setDigestValue(decodeBase64("3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs="));
        signaturePolicy.setDigestAlgorithm(SHA256);
        signaturePolicy.setSpuri("https://www.sk.ee/repository/bdoc-spec21.pdf");
        getSignatureParameters().bLevel().setSignaturePolicy(signaturePolicy);
    }

    private boolean isTimestampEmpty(XAdESSignature xAdESSignature) {
        List<TimestampToken> signatureTimestamps = xAdESSignature.getSignatureTimestamps();
        return signatureTimestamps == null || signatureTimestamps.size() == 0;
    }

    private String getSignaturePolicyQualifier(XAdESSignature xAdESSignature) {
        XPathQueryHolder xPathQueryHolder = xAdESSignature.getXPathQueryHolder();
        Element signatureElement = xAdESSignature.getSignatureElement();
        Element element = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_POLICY_IDENTIFIER);
        Element identifier = DSSXMLUtils.getElement(element, "./xades:SignaturePolicyId/xades:SigPolicyId/xades:Identifier");
        return identifier.getAttribute("Qualifier");
    }
}
