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
package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class CAdESExtensionInvalidLevelsTest extends AbstractCAdESTestExtension {

    private SignatureLevel originalSignatureLevel;
    private SignatureLevel finalSignatureLevel;

    @Test
    public void tLevelExtensionTest() throws Exception {
        originalSignatureLevel = SignatureLevel.CAdES_BASELINE_T;
        DSSDocument signedDocument = getSignedDocument(getOriginalDocument());
        Reports reports = verify(signedDocument);
        checkOriginalLevel(reports.getDiagnosticData());
        assertEquals(1, reports.getDiagnosticData().getTimestampList().size());

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_B;
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> extendSignature(signedDocument));
        assertEquals("Unsupported signature format 'CAdES-BASELINE-B' for extension.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_T;
        DSSDocument extendedSignature = extendSignature(signedDocument);
        reports = verify(extendedSignature);
        checkFinalLevel(reports.getDiagnosticData());
        assertEquals(2, reports.getDiagnosticData().getTimestampList().size());
    }

    @Test
    public void ltLevelExtensionTest() throws Exception {
        originalSignatureLevel = SignatureLevel.CAdES_BASELINE_LT;
        DSSDocument signedDocument = getSignedDocument(getOriginalDocument());
        Reports reports = verify(signedDocument);
        checkOriginalLevel(reports.getDiagnosticData());
        assertEquals(1, reports.getDiagnosticData().getTimestampList().size());

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_B;
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> extendSignature(signedDocument));
        assertEquals("Unsupported signature format 'CAdES-BASELINE-B' for extension.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_T;
        exception = assertThrows(IllegalInputException.class, () -> extendSignature(signedDocument));
        assertEquals("Cannot extend signature to 'CAdES-BASELINE-T'. The signedData is already extended with LT level.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_LT;
        DSSDocument extendedSignature = extendSignature(signedDocument);
        reports = verify(extendedSignature);
        checkFinalLevel(reports.getDiagnosticData());
        assertEquals(1, reports.getDiagnosticData().getTimestampList().size());
    }

    @Test
    public void ltaLevelExtensionTest() throws Exception {
        originalSignatureLevel = SignatureLevel.CAdES_BASELINE_LTA;
        DSSDocument signedDocument = getSignedDocument(getOriginalDocument());
        Reports reports = verify(signedDocument);
        checkOriginalLevel(reports.getDiagnosticData());
        assertEquals(2, reports.getDiagnosticData().getTimestampList().size());

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_B;
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> extendSignature(signedDocument));
        assertEquals("Unsupported signature format 'CAdES-BASELINE-B' for extension.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_T;
        exception = assertThrows(IllegalInputException.class, () -> extendSignature(signedDocument));
        assertEquals("Cannot extend signature to 'CAdES-BASELINE-T'. The signedData is already extended with LT level.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_LT;
        exception = assertThrows(IllegalInputException.class, () -> extendSignature(signedDocument));
        assertEquals("Cannot extend signature to 'CAdES-BASELINE-LT'. The signedData is already extended with LTA level.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.CAdES_BASELINE_LTA;
        DSSDocument extendedSignature = extendSignature(signedDocument);
        reports = verify(extendedSignature);
        checkFinalLevel(reports.getDiagnosticData());
        assertEquals(3, reports.getDiagnosticData().getTimestampList().size());
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return originalSignatureLevel;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return finalSignatureLevel;
    }

    @Override
    public void extendAndVerify() throws Exception {
        // do nothing
    }
    
}
