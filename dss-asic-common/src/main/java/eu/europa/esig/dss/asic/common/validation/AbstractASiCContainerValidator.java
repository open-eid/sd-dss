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
package eu.europa.esig.dss.asic.common.validation;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.ContainerInfo;
import eu.europa.esig.dss.validation.DiagnosticDataBuilder;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidator;
import eu.europa.esig.dss.validation.scope.SignatureScopeFinder;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The abstract class for an ASiC container validation
 */
public abstract class AbstractASiCContainerValidator extends SignedDocumentValidator {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractASiCContainerValidator.class);

	/** The container extraction result */
	protected ASiCContent asicContent;

	/** List of signature document validators */
	protected List<DocumentValidator> signatureValidators;

	/** List of timestamp document validators */
	protected List<DetachedTimestampValidator> timestampValidators;

	/** List of evidence record document validators */
	protected List<EvidenceRecordValidator> evidenceRecordValidators;

	/** List of manifest files */
	private List<ManifestFile> manifestFiles;

	/**
	 * Empty constructor
	 */
	protected AbstractASiCContainerValidator() {
		super();
	}

	/**
	 * The default constructor
	 * 
	 * @param document {@link DSSDocument} to be validated
	 */
	protected AbstractASiCContainerValidator(final DSSDocument document) {
		this.document = document;
		this.asicContent = extractEntries();
	}

	/**
	 * The constructor with {@code ASiCContent}
	 *
	 * @param asicContent {@link ASiCContent} to be validated
	 */
	protected AbstractASiCContainerValidator(final ASiCContent asicContent) {
		this.document = asicContent.getAsicContainer();
		this.asicContent = asicContent;
	}

	/**
	 * Constructor with a custom {@code SignatureScopeFinder}
	 * 
	 * @param document             {@link DSSDocument} to be validated
	 * @param signatureScopeFinder {@link SignatureScopeFinder} to be used
	 * @deprecated since DSS 5.13.
	 */
	@Deprecated
	protected AbstractASiCContainerValidator(final DSSDocument document,
			final SignatureScopeFinder<?> signatureScopeFinder) {
		this(document);
	}

	/**
	 * Constructor with a {@code ASiCContent}
	 *
	 * @param asicContent          {@link ASiCContent} to be validated
	 * @param signatureScopeFinder {@link SignatureScopeFinder} to be used
	 * @deprecated since DSS 5.13.
	 */
	@Deprecated
	protected AbstractASiCContainerValidator(final ASiCContent asicContent,
											 final SignatureScopeFinder<?> signatureScopeFinder) {
		this(asicContent);
	}

	/**
	 * Checks if the {@code ASiCContent} is supported by the current validator
	 *
	 * @param asicContent {@link ASiCContent} to check
	 * @return TRUE if the ASiC Content is supported, FALSE otherwise
	 */
	public abstract boolean isSupported(ASiCContent asicContent);

	/**
	 * Extracts documents from a container
	 */
	private ASiCContent extractEntries() {
		AbstractASiCContainerExtractor extractor = getContainerExtractor();
		return extractor.extract();
	}

	/**
	 * Returns the relevant container extractor
	 *
	 * @return {@link AbstractASiCContainerExtractor}
	 */
	protected abstract AbstractASiCContainerExtractor getContainerExtractor();
	
	@Override
	protected DiagnosticDataBuilder createDiagnosticDataBuilder(ValidationContext validationContext, List<AdvancedSignature> signatures,
																List<EvidenceRecord> evidenceRecords) {
		ASiCContainerDiagnosticDataBuilder builder = (ASiCContainerDiagnosticDataBuilder)
				super.createDiagnosticDataBuilder(validationContext, signatures, evidenceRecords);
		builder.containerInfo(getContainerInfo());
		return builder;
	}

	@Override
	protected ASiCContainerDiagnosticDataBuilder initializeDiagnosticDataBuilder() {
		return new ASiCContainerDiagnosticDataBuilder();
	}

	/**
	 * This method allows to retrieve the container information (ASiC Container)
	 * 
	 * @return a DTO with the container information
	 */
	protected ContainerInfo getContainerInfo() {
		ContainerInfo containerInfo = new ContainerInfo();
		containerInfo.setContainerType(asicContent.getContainerType());
		containerInfo.setZipComment(asicContent.getZipComment());

		DSSDocument mimeTypeDocument = asicContent.getMimeTypeDocument();
		if (mimeTypeDocument != null) {
			String mimeTypeContent = new String(DSSUtils.toByteArray(mimeTypeDocument));
			containerInfo.setMimeTypeContent(mimeTypeContent);
		}

		List<DSSDocument> originalSignedDocuments = asicContent.getSignedDocuments();
		if (Utils.isCollectionNotEmpty(originalSignedDocuments)) {
			List<String> signedDocumentFilenames = new ArrayList<>();
			for (DSSDocument dssDocument : originalSignedDocuments) {
				signedDocumentFilenames.add(dssDocument.getName());
			}
			containerInfo.setSignedDocumentFilenames(signedDocumentFilenames);
		}

		containerInfo.setManifestFiles(getManifestFiles());

		return containerInfo;
	}

	/**
	 * Attaches existing external timestamps to the list of {@code AdvancedSignature}s
	 *
	 * @param allSignatures list of {@link AdvancedSignature}s
	 * @return list of attached {@link TimestampToken}s
	 */
	protected List<TimestampToken> attachExternalTimestamps(List<AdvancedSignature> allSignatures) {
		// Not applicable by default (used only in ASiC CAdES)
		return Collections.emptyList();
	}

	/**
	 * Returns a list of parser ManifestFiles
	 *
	 * @return a list of {@link ManifestFile}s
	 */
	protected abstract List<ManifestFile> getManifestFilesDescriptions();

	@Override
	public List<AdvancedSignature> getAllSignatures() {
		final List<AdvancedSignature> allSignatureList = super.getAllSignatures();
		attachExternalTimestamps(allSignatureList);
		return allSignatureList;
	}

	@Override
	protected List<AdvancedSignature> buildSignatures() {
		final List<AdvancedSignature> signatureList = new ArrayList<>();
		for (DocumentValidator validator : getSignatureValidators()) {
			signatureList.addAll(validator.getSignatures());
		}
		
		return signatureList;
	}

	/**
	 * Returns a list of validators for signature documents embedded into the container
	 *
	 * @return a list of {@link DocumentValidator}s
	 */
	protected abstract List<DocumentValidator> getSignatureValidators();

	/**
	 * Returns a container type
	 *
	 * @return {@link ASiCContainerType}
	 */
	public ASiCContainerType getContainerType() {
		return asicContent.getContainerType();
	}

	/**
	 * Returns a list of all embedded  documents
	 *
	 * @return a list of all embedded {@link DSSDocument}s
	 */
	public List<DSSDocument> getAllDocuments() {
		return asicContent.getAllDocuments();
	}

	/**
	 * Returns a list of embedded signature documents
	 *
	 * @return a list of signature {@link DSSDocument}s
	 */
	public List<DSSDocument> getSignatureDocuments() {
		return asicContent.getSignatureDocuments();
	}

	/**
	 * Returns a list of embedded signed documents
	 *
	 * @return a list of signed {@link DSSDocument}s
	 */
	public List<DSSDocument> getSignedDocuments() {
		return asicContent.getSignedDocuments();
	}

	/**
	 * Returns a list of embedded signature manifest documents
	 *
	 * @return a list of signature manifest {@link DSSDocument}s
	 */
	public List<DSSDocument> getManifestDocuments() {
		return asicContent.getManifestDocuments();
	}

	/**
	 * Returns a list of embedded timestamp documents
	 *
	 * @return a list of timestamp {@link DSSDocument}s
	 */
	public List<DSSDocument> getTimestampDocuments() {
		return asicContent.getTimestampDocuments();
	}

	/**
	 * Returns a list of embedded evidence record documents
	 *
	 * @return a list of evidence record {@link DSSDocument}s
	 */
	public List<DSSDocument> getEvidenceRecordDocuments() {
		return asicContent.getEvidenceRecordDocuments();
	}

	/**
	 * Returns a list of embedded archive manifest documents
	 *
	 * @return a list of archive manifest {@link DSSDocument}s
	 */
	public List<DSSDocument> getArchiveManifestDocuments() {
		return asicContent.getArchiveManifestDocuments();
	}

	/**
	 * Returns a list of embedded evidence record manifest documents
	 *
	 * @return a list of evidence record manifest {@link DSSDocument}s
	 */
	public List<DSSDocument> getEvidenceRecordManifestDocuments() {
		return asicContent.getEvidenceRecordManifestDocuments();
	}

	/**
	 * Returns a list of all embedded manifest documents
	 *
	 * @return a list of manifest {@link DSSDocument}s
	 */
	public List<DSSDocument> getAllManifestDocuments() {
		return asicContent.getAllManifestDocuments();
	}

	/**
	 * Returns a list of archive documents embedded the container
	 *
	 * @return a list of archive {@link DSSDocument}s
	 */
	public List<DSSDocument> getArchiveDocuments() {
		return asicContent.getContainerDocuments();
	}

	/**
	 * Returns a mimetype document
	 *
	 * @return {@link DSSDocument} mimetype
	 */
	public DSSDocument getMimeTypeDocument() {
		return asicContent.getMimeTypeDocument();
	}

	/**
	 * Returns a list of unsupported documents from the container
	 *
	 * @return a list of unsupported documents {@link DSSDocument}s
	 */
	public List<DSSDocument> getUnsupportedDocuments() {
		return asicContent.getUnsupportedDocuments();
	}

	/**
	 * Returns a list of parser Manifest files
	 *
	 * @return a list of {@link ManifestFile}s
	 */
	public List<ManifestFile> getManifestFiles() {
		if (manifestFiles == null) {
			manifestFiles = getManifestFilesDescriptions();
		}
		return manifestFiles;
	}

	/**
	 * Returns a list of "package.zip" documents
	 *
	 * @param retrievedDocs the retrieved signed documents
	 * @return a list of {@link DSSDocument}s
	 */
	protected List<DSSDocument> getSignedDocumentsASiCS(List<DSSDocument> retrievedDocs) {
		List<DSSDocument> containerDocuments = asicContent.getContainerDocuments();
		if (Utils.isCollectionNotEmpty(containerDocuments)) {
			return containerDocuments;
		}
		return retrievedDocs;
	}

	@Override
	protected List<EvidenceRecord> buildDetachedEvidenceRecords() {
		final List<EvidenceRecord> embeddedEvidenceRecords = new ArrayList<>();
		for (EvidenceRecordValidator evidenceRecordValidator : getEvidenceRecordValidators()) {
			EvidenceRecord evidenceRecord = getEvidenceRecord(evidenceRecordValidator);
			if (evidenceRecord != null) {
				embeddedEvidenceRecords.add(evidenceRecord);
			}
		}
		final List<EvidenceRecord> detachedEvidenceRecords = new ArrayList<>(super.buildDetachedEvidenceRecords());
		attachExternalEvidenceRecords(embeddedEvidenceRecords, detachedEvidenceRecords);
		// return all
		detachedEvidenceRecords.addAll(embeddedEvidenceRecords);
		return detachedEvidenceRecords;
	}

	/**
	 * Appends detached evidence record provided to the validator to
	 * the evidence records covered by the corresponding evidence records
	 *
	 * @param embeddedEvidenceRecords a list of {@link EvidenceRecord}s extracted from the ASiC container
	 * @param detachedEvidenceRecords a list of {@link EvidenceRecord}s provided externally to the validation
	 */
	protected void attachExternalEvidenceRecords(List<EvidenceRecord> embeddedEvidenceRecords, List<EvidenceRecord> detachedEvidenceRecords) {
		if (Utils.isCollectionNotEmpty(embeddedEvidenceRecords)) {
			for (EvidenceRecord coveredEvidenceRecord : embeddedEvidenceRecords) {
				for (EvidenceRecord coveringEvidenceRecord : embeddedEvidenceRecords) {
					if (coversEvidenceRecord(coveredEvidenceRecord, coveringEvidenceRecord)) {
						coveredEvidenceRecord.addExternalEvidenceRecord(coveringEvidenceRecord);
					}
				}
				// assert all detached evidence records cover embedded data
				for (EvidenceRecord coveringEvidenceRecord : detachedEvidenceRecords) {
					coveredEvidenceRecord.addExternalEvidenceRecord(coveringEvidenceRecord);
				}
			}
		}
	}

	/**
	 * Builds and returns a list of evidence record validators
	 *
	 * @return a list of {@link EvidenceRecordValidator}
	 */
	protected List<EvidenceRecordValidator> getEvidenceRecordValidators() {
		if (evidenceRecordValidators == null) {
			evidenceRecordValidators = new ArrayList<>();
			for (final DSSDocument evidenceRecordDocument : getEvidenceRecordDocuments()) {
				EvidenceRecordValidator evidenceRecordValidator = getEvidenceRecordValidator(evidenceRecordDocument);
				if (evidenceRecordValidator != null) {
					evidenceRecordValidators.add(evidenceRecordValidator);
				}
			}
		}
		return evidenceRecordValidators;
	}

	private EvidenceRecordValidator getEvidenceRecordValidator(DSSDocument evidenceRecordDocument) {
		try {
			ManifestFile manifestFile = null;
			List<DSSDocument> detachedContents = getAllDocuments();

			DSSDocument evidenceRecordManifest = ASiCManifestParser.getLinkedManifest(
					getEvidenceRecordManifestDocuments(), evidenceRecordDocument.getName());
			if (evidenceRecordManifest != null) {
				manifestFile = getValidatedManifestFile(evidenceRecordManifest);
			}
			if (manifestFile == null) {
				List<DSSDocument> rootLevelSignedDocuments = ASiCUtils.getRootLevelSignedDocuments(asicContent);
				if (Utils.collectionSize(rootLevelSignedDocuments) == 1) {
					detachedContents = rootLevelSignedDocuments;
				} else {
					LOG.warn("A linked manifest is not found for an evidence record with name [{}]! Evidence record is skipped.",
							evidenceRecordDocument.getName());
					return null;
				}
			}

			final EvidenceRecordValidator evidenceRecordValidator = EvidenceRecordValidator.fromDocument(evidenceRecordDocument);
			evidenceRecordValidator.setDetachedContents(detachedContents);
			evidenceRecordValidator.setManifestFile(manifestFile);
			evidenceRecordValidator.setCertificateVerifier(certificateVerifier);
			return evidenceRecordValidator;

		} catch (Exception e) {
			LOG.warn("Unable to load EvidenceRecordValidator for an evidence record document with name '{}' : {}",
					evidenceRecordDocument.getName(), e.getMessage(), e);
			return null;
		}
	}

	@Override
	protected boolean coversSignature(AdvancedSignature signature, EvidenceRecord evidenceRecord) {
		ManifestFile evidenceRecordManifest = evidenceRecord.getManifestFile();
		if (evidenceRecordManifest == null) {
			// not embedded ER
			return true;
		}
		return coversFile(evidenceRecordManifest, signature.getSignatureFilename());
	}

	private boolean coversEvidenceRecord(EvidenceRecord coveredEvidenceRecord, EvidenceRecord coveringEvidenceRecord) {
		ManifestFile evidenceRecordManifest = coveringEvidenceRecord.getManifestFile();
		if (evidenceRecordManifest == null) {
			return false;
		}
		return coversFile(evidenceRecordManifest, coveredEvidenceRecord.getFilename());
	}

	private boolean coversFile(ManifestFile manifestFile, String filename) {
		if (manifestFile != null) {
			for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
				if (Utils.areStringsEqual(filename, manifestEntry.getFileName())) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Returns a validated {@code ManifestFile} for the given {@code manifest} document
	 *
	 * @param manifest {@link DSSDocument}
	 * @return {@link ManifestFile}
	 */
	protected ManifestFile getValidatedManifestFile(DSSDocument manifest) {
		List<ManifestFile> allManifestFiles = getManifestFiles();
		if (Utils.isCollectionNotEmpty(allManifestFiles)) {
			for (ManifestFile manifestFile : allManifestFiles) {
				if (Utils.areStringsEqual(manifest.getName(), manifestFile.getFilename())) {
					return manifestFile;
				}
			}
		}
		return null;
	}

	@Override
	protected boolean addReference(SignatureScope signatureScope) {
		String fileName = signatureScope.getDocumentName();
		return fileName == null || (!ASiCUtils.isSignature(fileName) && !ASiCUtils.isTimestamp(fileName) && !ASiCUtils.isEvidenceRecord(fileName));
	}

}
