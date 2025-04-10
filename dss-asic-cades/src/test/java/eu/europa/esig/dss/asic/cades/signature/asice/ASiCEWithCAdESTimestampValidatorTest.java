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
package eu.europa.esig.dss.asic.cades.signature.asice;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESTimestampValidator;
import eu.europa.esig.dss.asic.cades.validation.AbstractASiCWithCAdESTestValidation;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.validation.ASiCManifestParser;
import eu.europa.esig.dss.asic.common.validation.ASiCManifestValidator;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEWithCAdESTimestampValidatorTest extends AbstractASiCWithCAdESTestValidation {
	
	private static List<DSSDocument> documentsToSign;
	
	@BeforeEach
	public void init() {
		documentsToSign = new ArrayList<>();
		documentsToSign.add(new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT));
		documentsToSign.add(new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeTypeEnum.TEXT));
	}

	@Override
	protected DSSDocument getSignedDocument() {
		ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		ASiCWithCAdESService service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(documentsToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(documentsToSign, signatureParameters, signatureValue);
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		ASiCWithCAdESContainerExtractor containerExtractor = new ASiCWithCAdESContainerExtractor(signedDocument);
		ASiCContent asicContent = containerExtractor.extract();
		List<DSSDocument> timestampDocuments = asicContent.getTimestampDocuments();
		assertEquals(1, timestampDocuments.size());
		DSSDocument archiveTimestamp = timestampDocuments.get(0);
		
		List<DSSDocument> archiveManifestDocuments = asicContent.getArchiveManifestDocuments();
		assertEquals(1, archiveManifestDocuments.size());
		DSSDocument archiveManifest = archiveManifestDocuments.get(0);
		
		ManifestFile manifestFile = ASiCManifestParser.getManifestFile(archiveManifest);
		assertNotNull(manifestFile);

		ASiCManifestValidator manifestValidator = new ASiCManifestValidator(manifestFile, asicContent.getAllDocuments());
		manifestValidator.validateEntries();
		
		CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
		
		ASiCWithCAdESTimestampValidator asicWithCAdESTimestampValidator = new ASiCWithCAdESTimestampValidator(
				archiveTimestamp, TimestampType.CONTAINER_TIMESTAMP);
		asicWithCAdESTimestampValidator.setTimestampedData(archiveManifest);
		asicWithCAdESTimestampValidator.setManifestFile(manifestFile);
		asicWithCAdESTimestampValidator.setOriginalDocuments(documentsToSign);
		asicWithCAdESTimestampValidator.setCertificateVerifier(certificateVerifier);
		
		return asicWithCAdESTimestampValidator;
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);
		
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getTimestampIdList()));
		assertNotNull(simpleReport.getFirstTimestampId());
		String timestampId = simpleReport.getFirstTimestampId();
		assertNotNull(simpleReport.getCertificateChain(timestampId));
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getCertificateChain(timestampId).getCertificate()));
		assertNotNull(simpleReport.getProducedBy(timestampId));
		assertNotNull(simpleReport.getProductionTime(timestampId));
		assertNotNull(simpleReport.getValidationTime());
		assertFalse(Utils.isCollectionEmpty(simpleReport.getQualificationErrors(timestampId))); // qualification error message
	}
	
	@Override
	protected void verifyDetailedReport(DetailedReport detailedReport) {
		super.verifyDetailedReport(detailedReport);
		
		List<String> timestampIds = detailedReport.getTimestampIds();
		assertEquals(1, timestampIds.size());
		String timestampId = timestampIds.get(0);
		assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(timestampId));
		
		XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampId);
		assertNotNull(timestampBBB.getCertificateChain());
		assertEquals(2, timestampBBB.getCertificateChain().getChainItem().size());
		assertEquals(Indication.PASSED, timestampBBB.getConclusion().getIndication());
		
		assertTrue(Utils.isCollectionEmpty(timestampBBB.getConclusion().getErrors()));
		assertTrue(Utils.isCollectionEmpty(timestampBBB.getConclusion().getWarnings()));
		assertTrue(Utils.isCollectionEmpty(timestampBBB.getConclusion().getInfos()));

		XmlTimestamp xmlTimestamp = detailedReport.getXmlTimestampById(timestampId);
		XmlConclusion qualConslusion = xmlTimestamp.getValidationTimestampQualification().getConclusion();
		assertEquals(Indication.FAILED, qualConslusion.getIndication());
		assertFalse(Utils.isCollectionEmpty(qualConslusion.getErrors()));
	}
	
	@Override
	protected void verifyETSIValidationReport(ValidationReportType etsiValidationReportJaxb) {
		super.verifyETSIValidationReport(etsiValidationReportJaxb);
		
		List<SignatureValidationReportType> signatureValidationReports = etsiValidationReportJaxb.getSignatureValidationReport();
		assertNotNull(signatureValidationReports);
		assertEquals(1, signatureValidationReports.size());
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		assertTrue(Utils.isCollectionEmpty(signatures));
	}
	
	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		assertTrue(Utils.isCollectionEmpty(diagnosticData.getSignatures()));
	}
	
	@Override
	protected void checkContainerInfo(DiagnosticData diagnosticData) {
		assertNull(diagnosticData.getContainerInfo());
	}
	
	@Override
	protected void validateValidationStatus(ValidationStatusType signatureValidationStatus) {
		assertEquals(Indication.NO_SIGNATURE_FOUND, signatureValidationStatus.getMainIndication());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
