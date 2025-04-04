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
package eu.europa.esig.dss.xades.tsl;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TrustedListV5SignatureParametersBuilderWithMGFAndSHA512Test extends TrustedListV5SignatureParametersBuilderTest {

    @Override
    protected TrustedListV5SignatureParametersBuilder getSignatureParametersBuilder() {
        return super.getSignatureParametersBuilder()
                .setDigestAlgorithm(DigestAlgorithm.SHA512)
                .setMaskGenerationFunction(MaskGenerationFunction.MGF1);
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        super.checkBLevelValid(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        SignatureAlgorithm signatureAlgorithm = signature.getSignatureAlgorithm();
        assertEquals(SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, signatureAlgorithm);
    }

}
