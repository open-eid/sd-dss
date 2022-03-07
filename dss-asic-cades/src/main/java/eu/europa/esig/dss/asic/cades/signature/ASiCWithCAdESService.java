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
package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.manifest.ASiCEWithCAdESArchiveManifestBuilder;
import eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESValidator;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESExtractResultUtils;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESManifestParser;
import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.signature.ASiCCounterSignatureHelper;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCSignatureService;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESCounterSignatureBuilder;
import eu.europa.esig.dss.cades.signature.CAdESCounterSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CMSSignedDataBuilder;
import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.ValidationData;
import eu.europa.esig.dss.validation.ValidationDataContainer;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

/**
 * The service containing the main methods for ASiC with CAdES signature creation/extension
 */
@SuppressWarnings("serial")
public class ASiCWithCAdESService extends AbstractASiCSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters, 
						CAdESCounterSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCWithCAdESService.class);

	/** The default timestamp document name */
	private static final String ZIP_ENTRY_ASICE_METAINF_CADES_TIMESTAMP =
			ASiCUtils.META_INF_FOLDER + "timestamp001.tst";

	/** The default Archive Manifest filename */
	private static final String DEFAULT_ARCHIVE_MANIFEST_FILENAME =
			ASiCUtils.META_INF_FOLDER + ASiCUtils.ASIC_ARCHIVE_MANIFEST_FILENAME + ASiCUtils.XML_EXTENSION;

	/**
	 * The default constructor to instantiate the service
	 *
	 * @param certificateVerifier {@link CertificateVerifier} to use
	 */
	public ASiCWithCAdESService(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
		LOG.debug("+ ASiCService with CAdES created");
	}

	@Override
	public TimestampToken getContentTimestamp(List<DSSDocument> toSignDocuments, ASiCWithCAdESSignatureParameters parameters) {
		GetDataToSignASiCWithCAdESHelper getDataToSignHelper = new ASiCWithCAdESDataToSignHelperBuilder()
				.build(SigningOperation.SIGN, toSignDocuments, parameters);
		return getCAdESService().getContentTimestamp(getDataToSignHelper.getToBeSigned(), parameters);
	}

	@Override
	public ToBeSigned getDataToSign(List<DSSDocument> toSignDocuments, ASiCWithCAdESSignatureParameters parameters) {
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		if (Utils.isCollectionEmpty(toSignDocuments)) {
			throw new IllegalArgumentException("List of documents to sign cannot be empty!");
		}
		assertSigningDateInCertificateValidityRange(parameters);

		GetDataToSignASiCWithCAdESHelper dataToSignHelper = new ASiCWithCAdESDataToSignHelperBuilder()
				.build(SigningOperation.SIGN, toSignDocuments, parameters);
		assertSignaturePossible(dataToSignHelper, parameters.aSiC());

		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
		cadesParameters.setDetachedContents(dataToSignHelper.getDetachedContents());
		return getCAdESService().getDataToSign(dataToSignHelper.getToBeSigned(), cadesParameters);
	}

	@Override
	public DSSDocument signDocument(List<DSSDocument> toSignDocuments, ASiCWithCAdESSignatureParameters parameters,
									SignatureValue signatureValue) {
		Objects.requireNonNull(toSignDocuments, "toSignDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		Objects.requireNonNull(signatureValue, "SignatureValue cannot be null!");
		if (Utils.isCollectionEmpty(toSignDocuments)) {
			throw new IllegalArgumentException("List of documents to sign cannot be empty!");
		}

		assertSigningDateInCertificateValidityRange(parameters);

		GetDataToSignASiCWithCAdESHelper dataToSignHelper = new ASiCWithCAdESDataToSignHelperBuilder()
				.build(SigningOperation.SIGN, toSignDocuments, parameters);
		final ASiCParameters asicParameters = parameters.aSiC();
		assertSignaturePossible(dataToSignHelper, asicParameters);

		DSSDocument documentToExtend = dataToSignHelper.getAsicContainer();
		List<DSSDocument> signatures = dataToSignHelper.getSignatures();
		List<DSSDocument> manifests = dataToSignHelper.getManifestFiles();
		List<DSSDocument> archiveManifests = dataToSignHelper.getArchiveManifestFiles();
		List<DSSDocument> timestamps = dataToSignHelper.getTimestamps();

		List<DSSDocument> extendedDocuments = new ArrayList<>();

		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
		cadesParameters.setDetachedContents(dataToSignHelper.getDetachedContents());

		// Archive Timestamp in case of ASiC-E is not embedded into the CAdES signature
		boolean addASiCArchiveManifest = isAddASiCEArchiveManifest(parameters.getSignatureLevel(), parameters.aSiC().getContainerType());
		if (addASiCArchiveManifest) {
			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
		}

		final DSSDocument signature = getCAdESService().signDocument(dataToSignHelper.getToBeSigned(), cadesParameters, signatureValue);
		final String newSignatureFileName = dataToSignHelper.getSignatureFilename();
		signature.setName(newSignatureFileName);

		if (ASiCUtils.isASiCS(asicParameters)) {
			Iterator<DSSDocument> iterator = signatures.iterator();
			while (iterator.hasNext()) {
				if (Utils.areStringsEqual(newSignatureFileName, iterator.next().getName())) {
					// remove existing file to be replaced
					iterator.remove();
				}
			}
		}
		extendedDocuments.add(signature);
		if (documentToExtend == null) {
			documentToExtend = signature;
		}

		if (addASiCArchiveManifest) {
			extendWithArchiveManifest(documentToExtend, archiveManifests, manifests, timestamps, dataToSignHelper.getSignedDocuments(),
					extendedDocuments, parameters.getArchiveTimestampParameters().getDigestAlgorithm());
			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		}

		List<DSSDocument> documentsToStore = new ArrayList<>(manifests);
		documentsToStore.addAll(archiveManifests);
		documentsToStore.addAll(timestamps);
		documentsToStore.addAll(signatures);
		excludeExtendedDocuments(documentsToStore, extendedDocuments);
		final DSSDocument asicContainer = buildASiCContainer(dataToSignHelper.getSignedDocuments(), extendedDocuments, 
				documentsToStore, asicParameters, parameters.getZipCreationDate());
		asicContainer.setName(getFinalDocumentName(asicContainer, SigningOperation.SIGN, parameters.getSignatureLevel(), asicContainer.getMimeType()));
		parameters.reinitDeterministicId();
		return asicContainer;
	}

	@Override
	public DSSDocument timestamp(List<DSSDocument> toTimestampDocuments, ASiCWithCAdESTimestampParameters parameters) {
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		if (Utils.isCollectionEmpty(toTimestampDocuments)) {
			throw new IllegalArgumentException("List of documents to be timestamped cannot be empty!");
		}

		GetDataToSignASiCWithCAdESHelper dataToSignHelper = new ASiCWithCAdESDataToSignHelperBuilder()
				.build(SigningOperation.TIMESTAMP, toTimestampDocuments, parameters);
		ASiCParameters asicParameters = parameters.aSiC();
		assertTimestampPossible(dataToSignHelper, asicParameters);

		List<DSSDocument> timestamps = dataToSignHelper.getTimestamps();

		List<DSSDocument> extendedDocuments = new ArrayList<>();

		if (Utils.collectionSize(timestamps) > 0) {

			DSSDocument toTimestampDocument = toTimestampDocuments.get(0);
			extractCurrentArchive(toTimestampDocument);

			extendWithArchiveManifest(toTimestampDocument, getEmbeddedArchiveManifests(), getEmbeddedManifests(),
					getEmbeddedTimestamps(), getEmbeddedSignedDocuments(), extendedDocuments, parameters.getDigestAlgorithm());

			DSSDocument extensionResult = mergeArchiveAndExtendedSignatures(toTimestampDocument, extendedDocuments,
					parameters.getZipCreationDate(), ASiCUtils.getZipComment(asicParameters));
			extensionResult.setName(getFinalDocumentName(toTimestampDocument, SigningOperation.TIMESTAMP, null, toTimestampDocument.getMimeType()));
			return extensionResult;

		} else {

			List<DSSDocument> signatures = dataToSignHelper.getSignatures();
			List<DSSDocument> manifests = dataToSignHelper.getManifestFiles();
			List<DSSDocument> archiveManifests = dataToSignHelper.getArchiveManifestFiles();

			DSSDocument toBeSigned = dataToSignHelper.getToBeSigned();

			DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
			TimestampBinary timestampBinary = tspSource.getTimeStampResponse(digestAlgorithm, Utils.fromBase64(toBeSigned.getDigest(digestAlgorithm)));

			DSSDocument timestampToken = new InMemoryDocument(DSSASN1Utils.getDEREncoded(timestampBinary), dataToSignHelper.getTimestampFilename(),
					MimeType.TST);

			if (ASiCUtils.isASiCS(asicParameters)) {
				Iterator<DSSDocument> iterator = signatures.iterator();
				while (iterator.hasNext()) {
					if (Utils.areStringsEqual(timestampToken.getName(), iterator.next().getName())) {
						// remove existing file to be replaced
						iterator.remove();
					}
				}
			}
			extendedDocuments.add(timestampToken);

			List<DSSDocument> documentsToStore = new ArrayList<>(manifests);
			documentsToStore.addAll(archiveManifests);
			documentsToStore.addAll(timestamps);
			documentsToStore.addAll(signatures);
			excludeExtendedDocuments(documentsToStore, extendedDocuments);
			final DSSDocument asicContainer = buildASiCContainer(dataToSignHelper.getSignedDocuments(), extendedDocuments, 
					documentsToStore, asicParameters, parameters.getZipCreationDate());
			asicContainer.setName(getFinalDocumentName(asicContainer, SigningOperation.TIMESTAMP, null, asicContainer.getMimeType()));
			return asicContainer;

		}
	}

	private void excludeExtendedDocuments(List<DSSDocument> documentListToCheck, List<DSSDocument> extendedDocuments) {
		List<String> extendedDocumentNames = DSSUtils.getDocumentNames(extendedDocuments);
		Iterator<DSSDocument> iterator = documentListToCheck.iterator();
		while (iterator.hasNext()) {
			DSSDocument document = iterator.next();
			if (extendedDocumentNames.contains(document.getName())) {
				iterator.remove();
			}
		}
	}

	@Override
	public DSSDocument extendDocument(DSSDocument toExtendDocument, ASiCWithCAdESSignatureParameters parameters) {
		Objects.requireNonNull(toExtendDocument, "toExtendDocument is not defined!");
		Objects.requireNonNull(parameters, "Cannot extend the signature. SignatureParameters are not defined!");

		assertExtensionSupported(toExtendDocument);
		extractCurrentArchive(toExtendDocument);

		List<DSSDocument> signatureDocuments = getEmbeddedSignatures();
		assertValidSignaturesToExtendFound(signatureDocuments);

		List<DSSDocument> originalSignedDocuments = getEmbeddedSignedDocuments();
		DSSDocument mimetype = getEmbeddedMimetype();

		ASiCContainerType containerType = ASiCUtils.getContainerType(toExtendDocument, mimetype, null, originalSignedDocuments);
		if (containerType == null) {
			throw new IllegalInputException("The container type of the provided document is not supported or cannot be extracted!");
		}

		List<DSSDocument> extendedDocuments = new ArrayList<>();

		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);

		boolean addASiCEArchiveManifest = isAddASiCEArchiveManifest(parameters.getSignatureLevel(), containerType);
		if (addASiCEArchiveManifest) {
			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
		}

		for (DSSDocument signature : signatureDocuments) {
			// not to extend the signature itself when extending ASiC-E CAdES LTA
			if (!addASiCEArchiveManifest || !isCoveredByArchiveManifest(signature)) {
				DSSDocument extendedSignature = extendSignatureDocument(signature, cadesParameters, containerType);
				extendedDocuments.add(extendedSignature);
			} else {
				extendedDocuments.add(signature);
			}
		}

		if (addASiCEArchiveManifest) {
			extendWithArchiveManifest(toExtendDocument, getEmbeddedArchiveManifests(),
					getEmbeddedManifests(), getEmbeddedTimestamps(), getEmbeddedSignedDocuments(),
					extendedDocuments, parameters.getDigestAlgorithm());
			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		}

		DSSDocument extensionResult = mergeArchiveAndExtendedSignatures(toExtendDocument, extendedDocuments,
				parameters.getZipCreationDate(),
				ASiCUtils.getZipComment(parameters.aSiC()));
		extensionResult.setName(getFinalDocumentName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel(),
				toExtendDocument.getMimeType()));
		return extensionResult;
	}

	private void assertExtensionSupported(DSSDocument toExtendDocument) {
		if (!ASiCUtils.isZip(toExtendDocument)) {
			throw new IllegalInputException("Unsupported file type");
		}
	}

	private void assertValidSignaturesToExtendFound(List<DSSDocument> signatureDocuments) {
		if (Utils.isCollectionEmpty(signatureDocuments)) {
			throw new IllegalInputException("No supported signature documents found! Unable to extend the container.");
		}
	}

	private boolean isCoveredByArchiveManifest(DSSDocument signature) {
		return ASiCWithCAdESExtractResultUtils.isCoveredByManifest(archiveContent, signature.getName());
	}

	private DSSDocument extendSignatureDocument(DSSDocument signature, CAdESSignatureParameters cadesParameters, ASiCContainerType containerType) {

		List<DSSDocument> manifests = getEmbeddedManifests();
		List<DSSDocument> originalSignedDocuments = getEmbeddedSignedDocuments();

		if (ASiCContainerType.ASiC_E == containerType) {
			DSSDocument linkedManifest = ASiCWithCAdESManifestParser.getLinkedManifest(manifests, signature.getName());
			if (linkedManifest != null) {
				String originalName = signature.getName();
				cadesParameters.setDetachedContents(Arrays.asList(linkedManifest));

				DSSDocument extendDocument = getCAdESService().extendDocument(signature, cadesParameters);
				extendDocument.setName(originalName);
				return extendDocument;
			} else {
				LOG.warn("Manifest not found for signature file '{}' -> NOT EXTENDED !!!", signature.getName());
				return signature;
			}

		} else {
			String originalName = signature.getName();
			cadesParameters.setDetachedContents(originalSignedDocuments);

			DSSDocument extendDocument = getCAdESService().extendDocument(signature, cadesParameters);
			extendDocument.setName(originalName);
			return extendDocument;

		}
	}

	private void extendWithArchiveManifest(DSSDocument toExtendDocument, List<DSSDocument> archiveManifests,
			List<DSSDocument> manifests, List<DSSDocument> timestamps, List<DSSDocument> originalSignedDocuments,
			List<DSSDocument> extendedDocuments, DigestAlgorithm digestAlgorithm) {

		// shall be computed on the first step, before timestamp extension/creation
		String timestampFilename = getArchiveTimestampFilename(timestamps);

		manifests.addAll(archiveManifests);
		ManifestFile lastManifestFile = getLastManifestFile(manifests);
		DSSDocument lastTimestamp = getLastTimestampDocument(lastManifestFile, timestamps);
		if (lastTimestamp != null) {
			ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator(toExtendDocument);
			validator.setCertificateVerifier(certificateVerifier);

			final List<AdvancedSignature> allSignatures = validator.getAllSignatures();
			final List<TimestampToken> detachedTimestamps = validator.getDetachedTimestamps();

			ValidationDataContainer validationDataContainer = validator.getValidationData(allSignatures, detachedTimestamps);
			ValidationData allValidationData = validationDataContainer.getAllValidationData();

			// ensure the validation data is not duplicated
			if (Utils.isCollectionNotEmpty(extendedDocuments)) {
				for (DSSDocument documentToExtend : extendedDocuments) {
					allSignatures.addAll(new CMSDocumentValidator(documentToExtend).getSignatures());
				}
			}
			for (AdvancedSignature signature : allSignatures) {
				allValidationData.excludeCertificateTokens(signature.getCompleteCertificateSource().getAllCertificateTokens());
				allValidationData.excludeCRLTokens(signature.getCompleteCRLSource().getAllRevocationBinaries());
				allValidationData.excludeOCSPTokens(signature.getCompleteOCSPSource().getAllRevocationBinaries());
			}
			for (TimestampToken timestampToken : detachedTimestamps) {
				allValidationData.excludeCertificateTokens(timestampToken.getCertificateSource().getCertificates());
				allValidationData.excludeCRLTokens(timestampToken.getCRLSource().getAllRevocationBinaries());
				allValidationData.excludeOCSPTokens(timestampToken.getOCSPSource().getAllRevocationBinaries());
			}

			DSSDocument extendedTimestamp = extendTimestamp(lastTimestamp, allValidationData);
			// a newer version of the timestamp must be created
			timestamps.remove(lastTimestamp);
			extendedDocuments.add(extendedTimestamp);
		}

		DSSDocument lastArchiveManifest = null;
		if (lastManifestFile != null && isLastArchiveManifest(lastManifestFile.getFilename())) {
			lastArchiveManifest = lastManifestFile.getDocument();
			manifests.remove(lastArchiveManifest);
			lastArchiveManifest.setName(ASiCUtils.getNextASiCManifestName(ASiCUtils.ASIC_ARCHIVE_MANIFEST_FILENAME,
					archiveManifests));
		}

		ASiCEWithCAdESArchiveManifestBuilder builder = new ASiCEWithCAdESArchiveManifestBuilder(extendedDocuments,
				timestamps, originalSignedDocuments, manifests, lastArchiveManifest, digestAlgorithm, timestampFilename);

		DSSDocument archiveManifest = DomUtils.createDssDocumentFromDomDocument(builder.build(), DEFAULT_ARCHIVE_MANIFEST_FILENAME);
		extendedDocuments.add(archiveManifest);
		if (lastArchiveManifest != null) {
			extendedDocuments.add(lastArchiveManifest);
		}

		TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, DSSUtils.digest(digestAlgorithm, archiveManifest));
		DSSDocument timestamp = new InMemoryDocument(DSSASN1Utils.getDEREncoded(timeStampResponse), timestampFilename, MimeType.TST);
		extendedDocuments.add(timestamp);
	}

	private String getArchiveTimestampFilename(List<DSSDocument> timestamps) {
		int num = Utils.collectionSize(timestamps) + 1;
		return ZIP_ENTRY_ASICE_METAINF_CADES_TIMESTAMP.replace("001", ASiCUtils.getPadNumber(num));
	}

	private ManifestFile getLastManifestFile(List<DSSDocument> manifests) {
		DSSDocument lastManifest = getLastArchiveManifest(manifests);
		if (lastManifest == null) {
			lastManifest = DSSUtils.getDocumentWithLastName(manifests);
		}
		if (lastManifest != null) {
			return ASiCWithCAdESManifestParser.getManifestFile(lastManifest);
		}
		return null;
	}

	private DSSDocument getLastArchiveManifest(List<DSSDocument> manifests) {
		if (Utils.isCollectionNotEmpty(manifests)) {
			for (DSSDocument manifest : manifests) {
				if (isLastArchiveManifest(manifest.getName())) {
					return manifest;
				}
			}
		}
		return null;
	}

	private boolean isLastArchiveManifest(String fileName) {
		return DEFAULT_ARCHIVE_MANIFEST_FILENAME.equals(fileName);
	}

	private DSSDocument getLastTimestampDocument(ManifestFile lastManifestFile, List<DSSDocument> timestamps) {
		if (lastManifestFile != null) {
			return DSSUtils.getDocumentWithName(timestamps, lastManifestFile.getSignatureFilename());
		}
		return DSSUtils.getDocumentWithLastName(timestamps);
	}

	private DSSDocument extendTimestamp(DSSDocument archiveTimestamp, ValidationData validationDataForInclusion) {
		CMSSignedData cmsSignedData = DSSUtils.toCMSSignedData(archiveTimestamp);
		CMSSignedDataBuilder cmsSignedDataBuilder = new CMSSignedDataBuilder(certificateVerifier);
		CMSSignedData extendedCMSSignedData = cmsSignedDataBuilder.extendCMSSignedData(cmsSignedData, validationDataForInclusion);
		return new InMemoryDocument(DSSASN1Utils.getEncoded(extendedCMSSignedData), archiveTimestamp.getName(), MimeType.TST);
	}

	@Override
	protected AbstractASiCContainerExtractor getArchiveExtractor(DSSDocument archive) {
		return new ASiCWithCAdESContainerExtractor(archive);
	}

	private CAdESService getCAdESService() {
		CAdESService cadesService = new CAdESService(certificateVerifier);
		cadesService.setTspSource(tspSource);
		return cadesService;
	}

	private CAdESSignatureParameters getCAdESParameters(ASiCWithCAdESSignatureParameters parameters) {
		CAdESSignatureParameters cadesParameters = parameters;
		cadesParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		cadesParameters.setDetachedContents(null);
		return cadesParameters;
	}

	private boolean isAddASiCEArchiveManifest(SignatureLevel signatureLevel, ASiCContainerType containerType) {
		return SignatureLevel.CAdES_BASELINE_LTA == signatureLevel && ASiCContainerType.ASiC_E == containerType;
	}

	@Override
	protected String getExpectedSignatureExtension() {
		return ".p7s";
	}

	/**
	 * Incorporates a Signature Policy Store as an unsigned property into the ASiC
	 * with CAdES Signature
	 * 
	 * @param asicContainer        {@link DSSDocument} containing a CAdES Signature
	 *                             to add a SignaturePolicyStore to
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to add
	 * @return {@link DSSDocument} ASiC with CAdES container with an incorporated
	 *         SignaturePolicyStore
	 */
	public DSSDocument addSignaturePolicyStore(DSSDocument asicContainer, SignaturePolicyStore signaturePolicyStore) {
		Objects.requireNonNull(asicContainer, "The asicContainer cannot be null");
		Objects.requireNonNull(signaturePolicyStore, "The signaturePolicyStore cannot be null");

		extractCurrentArchive(asicContainer);
		assertAddSignaturePolicyStorePossible();

		CAdESService cadesService = getCAdESService();
		List<DSSDocument> extendedSignatures = new ArrayList<>();
		for (DSSDocument signature : getEmbeddedSignatures()) {
			DSSDocument signatureWithPolicyStore = cadesService.addSignaturePolicyStore(signature, signaturePolicyStore);
			signatureWithPolicyStore.setName(signature.getName());
			extendedSignatures.add(signatureWithPolicyStore);
		}

		DSSDocument resultArchive = mergeArchiveAndExtendedSignatures(asicContainer, extendedSignatures, null,
				ASiCUtils.getZipComment(asicContainer.getMimeType().getMimeTypeString()));
		resultArchive.setName(getFinalArchiveName(asicContainer, SigningOperation.ADD_SIG_POLICY_STORE, asicContainer.getMimeType()));
		return resultArchive;
	}
	
	@Override
	protected void assertAddSignaturePolicyStorePossible() {
		super.assertAddSignaturePolicyStorePossible();

		for (DSSDocument signature : getEmbeddedSignatures()) {
			if (isCoveredByArchiveManifest(signature)) {
				throw new IllegalInputException(String.format("Not possible to add a signature policy store! "
						+ "Reason : a signature with a filename '%s' is covered by another manifest.", signature.getName()));
			}
		}
	}

	@Override
	public ToBeSigned getDataToBeCounterSigned(DSSDocument asicContainer, CAdESCounterSignatureParameters parameters) {
		Objects.requireNonNull(asicContainer, "asicContainer cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		assertSigningDateInCertificateValidityRange(parameters);
		assertCounterSignatureParametersValid(parameters);

		ASiCCounterSignatureHelper counterSignatureHelper = new ASiCWithCAdESCounterSignatureHelper(asicContainer);
		DSSDocument signatureDocument = counterSignatureHelper.extractSignatureDocument(parameters.getSignatureIdToCounterSign());

		CAdESCounterSignatureBuilder counterSignatureBuilder = new CAdESCounterSignatureBuilder(certificateVerifier);
		counterSignatureBuilder.setManifestFile(counterSignatureHelper.getManifestFile(signatureDocument.getName()));
		
		SignerInformation signerInfoToCounterSign = counterSignatureBuilder.getSignerInformationToBeCounterSigned(signatureDocument, parameters);

		CAdESService cadesService = getCAdESService();
		return cadesService.getDataToBeCounterSigned(signatureDocument, signerInfoToCounterSign, parameters);
	}

	@Override
	public DSSDocument counterSignSignature(DSSDocument asicContainer, CAdESCounterSignatureParameters parameters,
			SignatureValue signatureValue) {
		Objects.requireNonNull(asicContainer, "asicContainer cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		Objects.requireNonNull(signatureValue, "signatureValue cannot be null!");
		assertCounterSignatureParametersValid(parameters);
		
		ASiCCounterSignatureHelper counterSignatureHelper = new ASiCWithCAdESCounterSignatureHelper(asicContainer);
		DSSDocument signatureDocument = counterSignatureHelper.extractSignatureDocument(parameters.getSignatureIdToCounterSign());

		CMSSignedData originalCMSSignedData = DSSUtils.toCMSSignedData(signatureDocument);
		
		CAdESCounterSignatureBuilder counterSignatureBuilder = new CAdESCounterSignatureBuilder(certificateVerifier);
		counterSignatureBuilder.setManifestFile(counterSignatureHelper.getManifestFile(signatureDocument.getName()));
		
		CMSSignedDocument counterSignedSignature = counterSignatureBuilder.addCounterSignature(originalCMSSignedData, parameters, signatureValue);
		counterSignedSignature.setName(signatureDocument.getName());
		
		List<DSSDocument> newSignaturesList = counterSignatureHelper.getUpdatedSignatureDocumentsList(counterSignedSignature);
		
		DSSDocument resultArchive = mergeArchiveAndExtendedSignatures(asicContainer, newSignaturesList,
				parameters.bLevel().getSigningDate(),
				ASiCUtils.getZipComment(asicContainer.getMimeType().getMimeTypeString()));
		resultArchive.setName(getFinalDocumentName(asicContainer, SigningOperation.COUNTER_SIGN, parameters.getSignatureLevel(), asicContainer.getMimeType()));
		return resultArchive;
	}

	@Override
	protected void assertCounterSignatureParametersValid(CAdESCounterSignatureParameters parameters) {
		super.assertCounterSignatureParametersValid(parameters);

		if (!SignatureLevel.CAdES_BASELINE_B.equals(parameters.getSignatureLevel())) {
			throw new UnsupportedOperationException(String.format("A counter signature with a level '%s' is not supported! "
					+ "Please, use CAdES-BASELINE-B", parameters.getSignatureLevel()));
		}
	}

	private void assertTimestampPossible(GetDataToSignASiCWithCAdESHelper dataToSignHelper, ASiCParameters asicParameters) {
		if (ASiCUtils.isASiCS(asicParameters) && Utils.isCollectionNotEmpty(dataToSignHelper.getSignatures())) {
			throw new IllegalInputException("Unable to timestamp an ASiC-S with CAdES container containing signature files! " +
					"Use extendDocument(...) method for signature extension.");
		}
	}

	private void assertSignaturePossible(GetDataToSignASiCWithCAdESHelper dataToSignHelper, ASiCParameters asicParameters) {
		if (ASiCUtils.isASiCS(asicParameters) && Utils.isCollectionNotEmpty(dataToSignHelper.getTimestamps())) {
			throw new IllegalInputException("Unable to sign an ASiC-S with CAdES container containing time assertion files!");
		}
	}

}
