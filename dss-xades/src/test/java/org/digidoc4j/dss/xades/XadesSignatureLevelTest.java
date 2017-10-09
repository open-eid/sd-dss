package org.digidoc4j.dss.xades;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.junit.Test;

import java.io.File;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class XadesSignatureLevelTest {

    @Test
    public void bDocTm_signatureLevel_shouldBe_lt() throws Exception {
        assertSignatureLevelEquals("src/test/resources/digidoc4j/test-bdoc-tm.xml", SignatureLevel.XAdES_BASELINE_LT);
    }

    @Test
    public void bDocTs_signatureLevel_shouldBe_lt() throws Exception {
        assertSignatureLevelEquals("src/test/resources/digidoc4j/test-bdoc-ts.xml", SignatureLevel.XAdES_BASELINE_LT);
    }

    @Test
    public void bDocEpes_signatureLevel_shouldBe_baselineB() throws Exception {
        assertSignatureLevelEquals("src/test/resources/digidoc4j/test-bdoc-epes.xml", SignatureLevel.XAdES_BASELINE_B);
    }

    private void assertSignatureLevelEquals(String documentPath, SignatureLevel expectedLevel) {
        XAdESSignature xadesSignature = openXadesSignature(documentPath);
        SignatureLevel signatureLevel = xadesSignature.getDataFoundUpToLevel();
        assertEquals(expectedLevel, signatureLevel);
    }

    private XAdESSignature openXadesSignature(String documentPath) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(new File(documentPath)));
        List<AdvancedSignature> signatureList = validator.getSignatures();
        return (XAdESSignature) signatureList.get(0);
    }
}
