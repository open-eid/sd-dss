package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelLTADetachedNoDataProvidedTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new FileDocument("src/test/resources/sample.xml");

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

        service = new XAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        TimestampToken contentTimestamp = service.getContentTimestamp(documentToSign, signatureParameters);
        signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signatureWrapper.isSignatureIntact());
        assertFalse(signatureWrapper.isSignatureValid());
        assertFalse(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));

        boolean signPropDMFound = false;
        boolean signDocDMFound = false;
        for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
            if (DigestMatcherType.SIGNED_PROPERTIES.equals(digestMatcher.getType())) {
                assertTrue(digestMatcher.isDataFound());
                assertTrue(digestMatcher.isDataIntact());
                signPropDMFound = true;
            } else if (DigestMatcherType.REFERENCE.equals(digestMatcher.getType())) {
                assertFalse(digestMatcher.isDataFound());
                assertFalse(digestMatcher.isDataIntact());
                signDocDMFound = true;
            }
        }
        assertTrue(signPropDMFound);
        assertTrue(signDocDMFound);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(3, timestampList.size());

        boolean cntTstFound = false;
        boolean sigTstFound = false;
        boolean arcTstFound = false;
        for (TimestampWrapper timestampWrapper : timestampList) {
            if (TimestampType.ALL_DATA_OBJECTS_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertFalse(timestampWrapper.isMessageImprintDataFound());
                assertFalse(timestampWrapper.isMessageImprintDataIntact());
                cntTstFound = true;
            } else if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                sigTstFound = true;
            } else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertFalse(timestampWrapper.isMessageImprintDataFound());
                assertFalse(timestampWrapper.isMessageImprintDataIntact());
                arcTstFound = true;
            }
        }
        assertTrue(cntTstFound);
        assertTrue(sigTstFound);
        assertTrue(arcTstFound);

    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
