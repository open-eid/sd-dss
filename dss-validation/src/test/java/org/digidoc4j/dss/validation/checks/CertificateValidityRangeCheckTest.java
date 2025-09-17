/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.digidoc4j.dss.validation.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.OidBasedEnum;
import eu.europa.esig.dss.enumerations.OidDescription;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateValidityRangeCheck;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.verification.VerificationMode;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

@ExtendWith(MockitoExtension.class)
class CertificateValidityRangeCheckTest {

    private static final Instant REFERENCE_TIME = Instant.now();

    private I18nProvider i18nProvider;
    @Mock
    private XmlConstraintsConclusion result;
    @Mock
    private CertificateWrapper certificate;

    private List<XmlConstraint> resultConstraint;

    @BeforeEach
    void setUp() {
        i18nProvider = new I18nProvider();

        resultConstraint = new ArrayList<>(1);
        doReturn(resultConstraint).when(result).getConstraint();
    }

    @Test
    void execute_WhenCertificateValid_IndeterminateNotRevoked() {
        stubCertificateAsValid(certificate);
        CertificateValidityRangeCheck<XmlConstraintsConclusion> rangeCheck = createRangeCheck(
                null, true, false
        );

        rangeCheck.execute();

        verifyConstraintAdded(XmlStatus.OK);
        verifyCertificateValidityQueried(certificate, atLeastOnce(), atLeastOnce());
        verifyNoMoreInteractions(result, certificate);
    }

    @Test
    void execute_WhenCertificateExpiredButNoRevocationDataRequired_IndeterminateNotRevoked() {
        stubCertificateAsExpired(certificate);
        CertificateValidityRangeCheck<XmlConstraintsConclusion> rangeCheck = createRangeCheck(
                null, false, false
        );

        rangeCheck.execute();

        verifyConstraintAdded(XmlStatus.NOT_OK);
        verifyIndeterminateConclusionRecorded(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED);
        verifyCertificateValidityQueried(certificate, atLeastOnce(), atLeastOnce());
        verifyNoMoreInteractions(result, certificate);
    }

    @Test
    void execute_WhenCertificateExpiredAndNoRevocationDataPresent_IndeterminateNoPoe() {
        stubCertificateAsExpired(certificate);
        CertificateValidityRangeCheck<XmlConstraintsConclusion> rangeCheck = createRangeCheck(
                null, true, false
        );

        rangeCheck.execute();

        verifyConstraintAdded(XmlStatus.NOT_OK);
        verifyIndeterminateConclusionRecorded(SubIndication.OUT_OF_BOUNDS_NO_POE);
        verifyCertificateValidityQueried(certificate, atLeastOnce(), atLeastOnce());
        verifyNoMoreInteractions(result, certificate);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void execute_WhenCertificateExpiredAndRevoked_IndeterminateNotRevoked(boolean revocationIssuerTrusted) {
        stubCertificateAsExpired(certificate);
        CertificateRevocationWrapper usedCertificateRevocation = mockCertificateRevocation(true, null);
        CertificateValidityRangeCheck<XmlConstraintsConclusion> rangeCheck = createRangeCheck(
                usedCertificateRevocation, true, revocationIssuerTrusted
        );

        rangeCheck.execute();

        verifyConstraintAdded(XmlStatus.NOT_OK);
        verifyIndeterminateConclusionRecorded(SubIndication.OUT_OF_BOUNDS_NO_POE);
        verifyCertificateValidityQueried(certificate, atLeastOnce(), atLeastOnce());
        verifyNoMoreInteractions(result, certificate, usedCertificateRevocation);
    }

    @Test
    void execute_WhenCertificateExpiredButRevocationIssuerTrusted_IndeterminateNotRevoked() {
        stubCertificateAsExpired(certificate);
        CertificateRevocationWrapper usedCertificateRevocation = mockCertificateRevocation(false, null);
        CertificateValidityRangeCheck<XmlConstraintsConclusion> rangeCheck = createRangeCheck(
                usedCertificateRevocation, true, true
        );

        rangeCheck.execute();

        verifyConstraintAdded(XmlStatus.NOT_OK);
        verifyIndeterminateConclusionRecorded(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED);
        verifyCertificateValidityQueried(certificate, atLeastOnce(), atLeastOnce());
        verifyNoMoreInteractions(result, certificate, usedCertificateRevocation);
    }

    @Test
    void execute_WhenCertificateExpiredAndRevocationCertificateNotPresent_IndeterminateNoPoe() {
        stubCertificateAsExpired(certificate);
        CertificateRevocationWrapper usedCertificateRevocation = mockCertificateRevocation(false, null);
        CertificateValidityRangeCheck<XmlConstraintsConclusion> rangeCheck = createRangeCheck(
                usedCertificateRevocation, true, false
        );

        rangeCheck.execute();

        verifyConstraintAdded(XmlStatus.NOT_OK);
        verifyIndeterminateConclusionRecorded(SubIndication.OUT_OF_BOUNDS_NO_POE);
        verifyCertificateValidityQueried(certificate, atLeastOnce(), atLeastOnce());
        verify(usedCertificateRevocation, atLeastOnce()).getSigningCertificate();
        verifyNoMoreInteractions(result, certificate, usedCertificateRevocation);
    }

    @Test
    void execute_WhenCertificateExpiredAndRevocationCertificateDatesNotPresent_IndeterminateNoPoe() {
        stubCertificateAsExpired(certificate);
        CertificateWrapper revocationCertificate = mock(CertificateWrapper.class);
        CertificateRevocationWrapper usedCertificateRevocation = mockCertificateRevocation(false, revocationCertificate);
        CertificateValidityRangeCheck<XmlConstraintsConclusion> rangeCheck = createRangeCheck(
                usedCertificateRevocation, true, false
        );

        rangeCheck.execute();

        verifyConstraintAdded(XmlStatus.NOT_OK);
        verifyIndeterminateConclusionRecorded(SubIndication.OUT_OF_BOUNDS_NO_POE);
        verifyCertificateValidityQueried(certificate, atLeastOnce(), atLeastOnce());
        verify(usedCertificateRevocation, atLeastOnce()).getSigningCertificate();
        verifyCertificateValidityQueried(revocationCertificate, times(2), times(1));
        verifyNoMoreInteractions(result, certificate, usedCertificateRevocation, revocationCertificate);
    }

    @Test
    void execute_WhenCertificateExpiredButRevocationCertificateValid_IndeterminateNotRevoked() {
        stubCertificateAsExpired(certificate);
        CertificateWrapper revocationCertificate = mock(CertificateWrapper.class);
        CertificateRevocationWrapper usedCertificateRevocation = mockCertificateRevocation(false, revocationCertificate);
        stubCertificateAsValid(revocationCertificate);
        CertificateValidityRangeCheck<XmlConstraintsConclusion> rangeCheck = createRangeCheck(
                usedCertificateRevocation, true, false
        );

        rangeCheck.execute();

        verifyConstraintAdded(XmlStatus.NOT_OK);
        verifyIndeterminateConclusionRecorded(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED);
        verifyCertificateValidityQueried(certificate, atLeastOnce(), atLeastOnce());
        verifyCertificateValidityQueried(revocationCertificate, times(1), times(1));
        verifyNoMoreInteractions(result, certificate, usedCertificateRevocation, revocationCertificate);
    }

    @Test
    void execute_WhenCertificateExpiredAndRevocationCertificateNotYetValid_IndeterminateNoPoe() {
        stubCertificateAsExpired(certificate);
        CertificateWrapper revocationCertificate = mock(CertificateWrapper.class);
        CertificateRevocationWrapper usedCertificateRevocation = mockCertificateRevocation(false, revocationCertificate);
        stubCertificateAsNotYetValid(revocationCertificate);
        CertificateValidityRangeCheck<XmlConstraintsConclusion> rangeCheck = createRangeCheck(
                usedCertificateRevocation, true, false
        );

        rangeCheck.execute();

        verifyConstraintAdded(XmlStatus.NOT_OK);
        verifyIndeterminateConclusionRecorded(SubIndication.OUT_OF_BOUNDS_NO_POE);
        verifyCertificateValidityQueried(certificate, atLeastOnce(), atLeastOnce());
        verifyCertificateValidityQueried(revocationCertificate, times(2), times(1));
        verifyNoMoreInteractions(result, certificate, usedCertificateRevocation, revocationCertificate);
    }

    @Test
    void execute_WhenCertificateAndRevocationExpiredAndIsCa_IndeterminateNoPoe() {
        stubCertificateAsExpired(certificate);
        CertificateWrapper revocationCertificate = mock(CertificateWrapper.class);
        CertificateRevocationWrapper usedCertificateRevocation = mockCertificateRevocation(false, revocationCertificate);
        stubCertificateAsExpired(revocationCertificate);
        doReturn(true).when(certificate).isCA();
        CertificateValidityRangeCheck<XmlConstraintsConclusion> rangeCheck = createRangeCheck(
                usedCertificateRevocation, true, false
        );

        rangeCheck.execute();

        verifyConstraintAdded(XmlStatus.NOT_OK);
        verifyIndeterminateConclusionRecorded(SubIndication.OUT_OF_BOUNDS_NO_POE);
        verifyCertificateValidityQueried(certificate, atLeastOnce(), atLeastOnce());
        verifyCertificateValidityQueried(revocationCertificate, times(2), times(1));
        verifyNoMoreInteractions(result, certificate, usedCertificateRevocation, revocationCertificate);
    }

    @Test
    void execute_WhenCertificateAndRevocationExpiredAndNotNonRepudiation_IndeterminateNoPoe() {
        stubCertificateAsExpired(certificate);
        CertificateWrapper revocationCertificate = mock(CertificateWrapper.class);
        CertificateRevocationWrapper usedCertificateRevocation = mockCertificateRevocation(false, revocationCertificate);
        stubCertificateAsExpired(revocationCertificate);
        doReturn(false).when(certificate).isCA();
        doReturn(Collections.emptyList()).when(certificate).getKeyUsages();
        CertificateValidityRangeCheck<XmlConstraintsConclusion> rangeCheck = createRangeCheck(
                usedCertificateRevocation, true, false
        );

        rangeCheck.execute();

        verifyConstraintAdded(XmlStatus.NOT_OK);
        verifyIndeterminateConclusionRecorded(SubIndication.OUT_OF_BOUNDS_NO_POE);
        verifyCertificateValidityQueried(certificate, atLeastOnce(), atLeastOnce());
        verifyCertificateValidityQueried(revocationCertificate, times(2), times(1));
        verifyNoMoreInteractions(result, certificate, usedCertificateRevocation, revocationCertificate);
    }

    @ParameterizedTest
    @MethodSource("nonSigningCertificateExtendedKeyUsageOids")
    void execute_WhenCertificateAndRevocationExpiredAndHasUnallowedExtendedKeyUsage_IndeterminateNoPoe(
            List<ExtendedKeyUsage> certificateExtendedKeyUsages
    ) {
        stubCertificateAsExpired(certificate);
        CertificateWrapper revocationCertificate = mock(CertificateWrapper.class);
        CertificateRevocationWrapper usedCertificateRevocation = mockCertificateRevocation(false, revocationCertificate);
        stubCertificateAsExpired(revocationCertificate);
        doReturn(false).when(certificate).isCA();
        doReturn(Collections.singletonList(KeyUsageBit.NON_REPUDIATION)).when(certificate).getKeyUsages();
        doReturn(mapToXmlOidList(certificateExtendedKeyUsages)).when(certificate).getExtendedKeyUsages();
        CertificateValidityRangeCheck<XmlConstraintsConclusion> rangeCheck = createRangeCheck(
                usedCertificateRevocation, true, false
        );

        rangeCheck.execute();

        verifyConstraintAdded(XmlStatus.NOT_OK);
        verifyIndeterminateConclusionRecorded(SubIndication.OUT_OF_BOUNDS_NO_POE);
        verifyCertificateValidityQueried(certificate, atLeastOnce(), atLeastOnce());
        verifyCertificateValidityQueried(revocationCertificate, times(2), times(1));
        verifyNoMoreInteractions(result, certificate, usedCertificateRevocation, revocationCertificate);
    }

    @ParameterizedTest
    @MethodSource("signingCertificateKeyUsagesAndExtendedKeyUsagesAndValidSunsetDates")
    void execute_WhenCertificateAndRevocationExpiredButIssuerTrusted_IndeterminateNotRevoked(
            List<KeyUsageBit> certificateKeyUsages,
            List<ExtendedKeyUsage> certificateExtendedKeyUsages,
            Date issuerSunsetDate
    ) {
        stubCertificateAsExpired(certificate);
        CertificateWrapper revocationCertificate = mock(CertificateWrapper.class);
        CertificateRevocationWrapper usedCertificateRevocation = mockCertificateRevocation(false, revocationCertificate);
        stubCertificateAsExpired(revocationCertificate);
        doReturn(false).when(certificate).isCA();
        doReturn(certificateKeyUsages).when(certificate).getKeyUsages();
        doReturn(mapToXmlOidList(certificateExtendedKeyUsages)).when(certificate).getExtendedKeyUsages();
        CertificateWrapper issuerCertificate = mock(CertificateWrapper.class);
        doReturn(issuerCertificate).when(certificate).getSigningCertificate();
        doReturn(true).when(issuerCertificate).isTrusted();
        doReturn(issuerSunsetDate).when(issuerCertificate).getTrustSunsetDate();
        CertificateValidityRangeCheck<XmlConstraintsConclusion> rangeCheck = createRangeCheck(
                usedCertificateRevocation, true, false
        );

        rangeCheck.execute();

        verifyConstraintAdded(XmlStatus.NOT_OK);
        verifyIndeterminateConclusionRecorded(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED);
        verifyCertificateValidityQueried(certificate, atLeastOnce(), atLeastOnce());
        verifyCertificateValidityQueried(revocationCertificate, times(2), times(1));
        verifyNoMoreInteractions(result, certificate, usedCertificateRevocation, revocationCertificate, issuerCertificate);
    }

    static Stream<Arguments> signingCertificateKeyUsagesAndExtendedKeyUsagesAndValidSunsetDates() {
        return signingCertificateKeyUsagesAndExtendedKeyUsages()
                .flatMap(args -> validSunsetDates()
                        .map(sd -> append(args, sd))
                );
    }

    @ParameterizedTest
    @MethodSource("signingCertificateKeyUsagesAndExtendedKeyUsages")
    void execute_WhenCertificateAndRevocationExpiredButIssuerCertificateValid_IndeterminateNotRevoked(
            List<KeyUsageBit> certificateKeyUsages,
            List<ExtendedKeyUsage> certificateExtendedKeyUsages
    ) {
        stubCertificateAsExpired(certificate);
        CertificateWrapper revocationCertificate = mock(CertificateWrapper.class);
        CertificateRevocationWrapper usedCertificateRevocation = mockCertificateRevocation(false, revocationCertificate);
        stubCertificateAsExpired(revocationCertificate);
        doReturn(false).when(certificate).isCA();
        doReturn(certificateKeyUsages).when(certificate).getKeyUsages();
        doReturn(mapToXmlOidList(certificateExtendedKeyUsages)).when(certificate).getExtendedKeyUsages();
        CertificateWrapper issuerCertificate = mock(CertificateWrapper.class);
        doReturn(issuerCertificate).when(certificate).getSigningCertificate();
        doReturn(false).when(issuerCertificate).isTrusted();
        stubCertificateAsValid(issuerCertificate);
        CertificateValidityRangeCheck<XmlConstraintsConclusion> rangeCheck = createRangeCheck(
                usedCertificateRevocation, true, false
        );

        rangeCheck.execute();

        verifyConstraintAdded(XmlStatus.NOT_OK);
        verifyIndeterminateConclusionRecorded(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED);
        verifyCertificateValidityQueried(certificate, atLeastOnce(), atLeastOnce());
        verifyCertificateValidityQueried(revocationCertificate, times(2), times(1));
        verifyNoMoreInteractions(result, certificate, usedCertificateRevocation, revocationCertificate, issuerCertificate);
    }

    @ParameterizedTest
    @MethodSource("invalidCertificateValidityDates")
    void execute_WhenCertificateAndRevocationExpiredAndIssuerCertificateInvalid_IndeterminateNoPoe(
            Date issuerCertificateNotBefore,
            Date issuerCertificateNotAfter
    ) {
        stubCertificateAsExpired(certificate);
        CertificateWrapper revocationCertificate = mock(CertificateWrapper.class);
        CertificateRevocationWrapper usedCertificateRevocation = mockCertificateRevocation(false, revocationCertificate);
        stubCertificateAsExpired(revocationCertificate);
        doReturn(false).when(certificate).isCA();
        doReturn(Collections.singletonList(KeyUsageBit.NON_REPUDIATION)).when(certificate).getKeyUsages();
        doReturn(Collections.emptyList()).when(certificate).getExtendedKeyUsages();
        CertificateWrapper issuerCertificate = mock(CertificateWrapper.class);
        doReturn(issuerCertificate).when(certificate).getSigningCertificate();
        doReturn(false).when(issuerCertificate).isTrusted();
        stubCertificateValidity(issuerCertificate, issuerCertificateNotBefore, issuerCertificateNotAfter);
        CertificateValidityRangeCheck<XmlConstraintsConclusion> rangeCheck = createRangeCheck(
                usedCertificateRevocation, true, false
        );

        rangeCheck.execute();

        verifyConstraintAdded(XmlStatus.NOT_OK);
        verifyIndeterminateConclusionRecorded(SubIndication.OUT_OF_BOUNDS_NO_POE);
        verifyCertificateValidityQueried(certificate, atLeastOnce(), atLeastOnce());
        verifyCertificateValidityQueried(revocationCertificate, times(2), times(1));
        verifyNoMoreInteractions(result, certificate, usedCertificateRevocation, revocationCertificate, issuerCertificate);
    }

    private CertificateValidityRangeCheck<XmlConstraintsConclusion> createRangeCheck(
            CertificateRevocationWrapper usedCertificateRevocation,
            boolean revocationDataRequired,
            boolean revocationIssuerTrusted
    ) {
        LevelConstraint failLevelConstraint = new LevelConstraint();
        failLevelConstraint.setLevel(Level.FAIL);

        return new CertificateValidityRangeCheck<>(
                i18nProvider, result, certificate, usedCertificateRevocation, revocationDataRequired,
                revocationIssuerTrusted, Date.from(REFERENCE_TIME), failLevelConstraint
        );
    }

    private static Arguments append(Arguments initial, Object... additional) {
        return Arguments.of(Stream
                .of(initial.get(), additional)
                .flatMap(Stream::of)
                .toArray(Object[]::new)
        );
    }

    private static XmlOID createXmlOid(OidBasedEnum oid) {
        XmlOID xmlOID = new XmlOID();
        xmlOID.setValue(oid.getOid());
        if (oid instanceof OidDescription) {
            xmlOID.setDescription(((OidDescription) oid).getDescription());
        }
        return xmlOID;
    }

    private static List<XmlOID> mapToXmlOidList(List<? extends OidBasedEnum> oidList) {
        return Collections.unmodifiableList(oidList.stream()
                .map(CertificateValidityRangeCheckTest::createXmlOid)
                .collect(Collectors.toList()));
    }

    private static CertificateRevocationWrapper mockCertificateRevocation(
            boolean isRevoked,
            CertificateWrapper revocationCertificate
    ) {
        CertificateRevocationWrapper certificateRevocation = mock(CertificateRevocationWrapper.class);
        doReturn(isRevoked).when(certificateRevocation).isRevoked();
        if (revocationCertificate != null) {
            doReturn(revocationCertificate).when(certificateRevocation).getSigningCertificate();
        }
        return certificateRevocation;
    }

    private static void stubCertificateAsExpired(CertificateWrapper certificateWrapperMock) {
        stubCertificateValidity(certificateWrapperMock,
                Date.from(REFERENCE_TIME.minus(2, ChronoUnit.MINUTES)),
                Date.from(REFERENCE_TIME.minus(1, ChronoUnit.MINUTES))
        );
    }

    private static void stubCertificateAsValid(CertificateWrapper certificateWrapperMock) {
        stubCertificateValidity(certificateWrapperMock,
                Date.from(REFERENCE_TIME.minus(1, ChronoUnit.MINUTES)),
                Date.from(REFERENCE_TIME.plus(1, ChronoUnit.MINUTES))
        );
    }

    private static void stubCertificateAsNotYetValid(CertificateWrapper certificateWrapperMock) {
        stubCertificateValidity(certificateWrapperMock,
                Date.from(REFERENCE_TIME.plus(1, ChronoUnit.MINUTES)),
                Date.from(REFERENCE_TIME.plus(2, ChronoUnit.MINUTES))
        );
    }

    private static void stubCertificateValidity(
            CertificateWrapper certificateWrapperMock,
            Date certificateNotBefore,
            Date certificateNotAfter
    ) {
        doReturn(certificateNotBefore).when(certificateWrapperMock).getNotBefore();
        doReturn(certificateNotAfter).when(certificateWrapperMock).getNotAfter();
    }

    private static void verifyCertificateValidityQueried(
            CertificateWrapper certificateWrapperMock,
            VerificationMode expectedVerificationModeForNotBefore,
            VerificationMode expectedVerificationModeForNotAfter
    ) {
        if (expectedVerificationModeForNotBefore != null) {
            verify(certificateWrapperMock, expectedVerificationModeForNotBefore).getNotBefore();
        }
        if (expectedVerificationModeForNotAfter != null) {
            verify(certificateWrapperMock, expectedVerificationModeForNotAfter).getNotAfter();
        }
    }

    private void verifyConstraintAdded(XmlStatus expectedStatus) {
        verify(result).getConstraint();

        assertEquals(1, resultConstraint.size());
        assertNotNull(resultConstraint.get(0));

        XmlConstraint constraint = resultConstraint.get(0);
        assertNotNull(constraint.getName());

        assertEquals(MessageTag.BBB_XCV_ICTIVRSC.getId(), constraint.getName().getKey());
        assertEquals(i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC), constraint.getName().getValue());
        assertSame(expectedStatus, constraint.getStatus());
    }

    private void verifyIndeterminateConclusionRecorded(SubIndication expectedSubIndication) {
        ArgumentCaptor<XmlConclusion> conclusionCaptor = ArgumentCaptor.forClass(XmlConclusion.class);
        verify(result).setConclusion(conclusionCaptor.capture());

        XmlConclusion capturedConclusion = conclusionCaptor.getValue();
        assertNotNull(capturedConclusion);

        assertSame(Indication.INDETERMINATE, capturedConclusion.getIndication());
        assertSame(expectedSubIndication, capturedConclusion.getSubIndication());
    }

    static Stream<Arguments> invalidCertificateValidityDates() {
        return Stream.of(
                Arguments.of(null, null),
                Arguments.of(
                        Date.from(REFERENCE_TIME.minus(1, ChronoUnit.MINUTES)),
                        null
                ),
                Arguments.of(
                        null,
                        Date.from(REFERENCE_TIME.plus(1, ChronoUnit.MINUTES))
                ),
                Arguments.of(
                        Date.from(REFERENCE_TIME.minus(2, ChronoUnit.MINUTES)),
                        Date.from(REFERENCE_TIME.minus(1, ChronoUnit.MINUTES))
                ),
                Arguments.of(
                        Date.from(REFERENCE_TIME.plus(1, ChronoUnit.MINUTES)),
                        Date.from(REFERENCE_TIME.plus(2, ChronoUnit.MINUTES))
                )
        );
    }

    static Stream<Arguments> signingCertificateKeyUsagesAndExtendedKeyUsages() {
        return signingCertificateKeyUsageBits()
                .flatMap(ku -> signingCertificateExtendedKeyUsageOids()
                        .map(eku -> Arguments.of(ku, eku))
                );
    }

    static Stream<List<KeyUsageBit>> signingCertificateKeyUsageBits() {
        return Stream.of(
                Collections.singletonList(KeyUsageBit.NON_REPUDIATION),
                Collections.unmodifiableList(Arrays.asList(KeyUsageBit.values()))
        );
    }

    static Stream<List<ExtendedKeyUsage>> signingCertificateExtendedKeyUsageOids() {
        return Stream.of(
                Collections.emptyList(),
                Collections.unmodifiableList(Stream
                        .of(ExtendedKeyUsage.values())
                        .filter(eku -> eku != ExtendedKeyUsage.OCSP_SIGNING)
                        .filter(eku -> eku != ExtendedKeyUsage.TIMESTAMPING)
                        .collect(Collectors.toList()))
        );
    }

    static Stream<List<ExtendedKeyUsage>> nonSigningCertificateExtendedKeyUsageOids() {
        return Stream.of(
                Collections.singletonList(ExtendedKeyUsage.OCSP_SIGNING),
                Collections.singletonList(ExtendedKeyUsage.TIMESTAMPING),
                Collections.unmodifiableList(Stream
                        .of(ExtendedKeyUsage.values())
                        .filter(eku -> eku != ExtendedKeyUsage.OCSP_SIGNING)
                        .collect(Collectors.toList())),
                Collections.unmodifiableList(Stream
                        .of(ExtendedKeyUsage.values())
                        .filter(eku -> eku != ExtendedKeyUsage.TIMESTAMPING)
                        .collect(Collectors.toList())),
                Collections.unmodifiableList(Arrays.asList(ExtendedKeyUsage.values()))
        );
    }

    static Stream<Date> validSunsetDates() {
        return Stream.of(
                null,
                Date.from(REFERENCE_TIME.plus(1, ChronoUnit.MINUTES))
        );
    }

}
