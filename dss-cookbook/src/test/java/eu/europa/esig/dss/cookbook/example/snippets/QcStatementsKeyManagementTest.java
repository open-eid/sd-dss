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
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.extension.QcStatements;
import eu.europa.esig.dss.spi.QcStatementUtils;
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.predicate.DSSKeyEntryPredicate;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class QcStatementsKeyManagementTest {

    @Test
    public void qscdTest() throws IOException {

        try (AbstractKeyStoreTokenConnection token = new Pkcs12SignatureToken("src/test/resources/john-doe.p12",
                new KeyStore.PasswordProtection("ks-password".toCharArray()))) {
            // tag::qcQscdPredicateUsage[]
            // Use of custom DSSKeyEntryPredicate
            token.setKeyEntryPredicate(new QcQSCDKeyEntryPredicate());
            // end::qcQscdPredicateUsage[]
            assertEquals(1, token.getKeys().size());
        }

    }

    @Test
    public void nonQscdTest() throws IOException {

        try (AbstractKeyStoreTokenConnection token = new Pkcs12SignatureToken("src/test/resources/bob-doe.p12",
                new KeyStore.PasswordProtection("ks-password".toCharArray()))) {
            token.setKeyEntryPredicate(new QcQSCDKeyEntryPredicate());
            assertEquals(0, token.getKeys().size());
        }

    }

    // tag::qcQscdPredicate[]
    // import eu.europa.esig.dss.model.x509.CertificateToken;
    // import eu.europa.esig.dss.model.x509.extension.QcStatements;
    // import eu.europa.esig.dss.spi.QcStatementUtils;
    // import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
    // import eu.europa.esig.dss.token.predicate.DSSKeyEntryPredicate;

    public static class QcQSCDKeyEntryPredicate implements DSSKeyEntryPredicate {

        @Override
        public boolean test(DSSPrivateKeyEntry dssPrivateKeyEntry) {
            CertificateToken certificate = dssPrivateKeyEntry.getCertificate();
            if (certificate != null) {
                QcStatements qcStatements = QcStatementUtils.getQcStatements(certificate);
                return qcStatements != null && qcStatements.isQcQSCD();
            }
            return false;
        }

    }
    // end::qcQscdPredicate[]

}
