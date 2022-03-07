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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JWSJsonSerializationGenerator;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.validation.AbstractJWSDocumentValidator;
import eu.europa.esig.dss.jades.validation.JAdESDocumentValidatorFactory;
import eu.europa.esig.dss.jades.validation.JAdESEtsiUHeader;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignaturePolicy;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The builder used to incorporate a {@code SignaturePolicyStore} to a
 * JAdESSignature document
 *
 */
public class JAdESSignaturePolicyStoreBuilder extends JAdESExtensionBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESSignaturePolicyStoreBuilder.class);

	/**
	 * Adds {@code signaturePolicyStore} to signatures inside the {@code document}
	 * 
	 * @param document             {@link DSSDocument} containing JAdES signatures
	 *                             to extend with a {@link SignaturePolicyStore}
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to incorporate
	 * @param base64UrlInstance    TRUE if the signature policy store shall be
	 *                             incorporated as a base64url encoded component of
	 *                             the 'etsiU' header, FALSE if it will be
	 *                             incorporated in its clear JSON representation
	 * @return {@link DSSDocument} containing signatures with
	 *         {@code signaturePolicyStore}
	 */
	public DSSDocument addSignaturePolicyStore(DSSDocument document, SignaturePolicyStore signaturePolicyStore, boolean base64UrlInstance) {
		Objects.requireNonNull(signaturePolicyStore, "SignaturePolicyStore must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification(), "SpDocSpecification must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification().getId(), "ID (OID or URI) for SpDocSpecification must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSignaturePolicyContent(), "Signature policy content must be provided");

		JAdESDocumentValidatorFactory documentValidatorFactory = new JAdESDocumentValidatorFactory();
		AbstractJWSDocumentValidator documentValidator = documentValidatorFactory.create(document);

		JWSJsonSerializationObject jwsJsonSerializationObject = documentValidator.getJwsJsonSerializationObject();
		assertJSONSerializationObjectMayBeExtended(jwsJsonSerializationObject);

		List<AdvancedSignature> signatures = documentValidator.getSignatures();

		for (AdvancedSignature signature : signatures) {
			JAdESSignature jadesSignature = (JAdESSignature) signature;
			assertEtsiUComponentsConsistent(jadesSignature.getJws(), base64UrlInstance);

			extendSignature(jadesSignature, signaturePolicyStore, base64UrlInstance, documentValidator);
		}

		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject,
				jwsJsonSerializationObject.getJWSSerializationType());
		return generator.generate();
	}

	private void extendSignature(JAdESSignature jadesSignature, SignaturePolicyStore signaturePolicyStore, boolean base64UrlInstance,
								 AbstractJWSDocumentValidator documentValidator) {
		SignaturePolicy signaturePolicy = jadesSignature.getSignaturePolicy();
		if (signaturePolicy != null && signaturePolicy.getDigest() != null) {
			signaturePolicy.setPolicyContent(signaturePolicyStore.getSignaturePolicyContent());
			Digest expectedDigest = signaturePolicy.getDigest();

			SignaturePolicyValidator signaturePolicyValidator = documentValidator.getSignaturePolicyValidatorLoader().loadValidator(signaturePolicy);
			Digest computedDigest = signaturePolicyValidator.getComputedDigest(signaturePolicyStore.getSignaturePolicyContent(),
					expectedDigest.getAlgorithm());
			if (expectedDigest.equals(computedDigest)) {

				Map<String, Object> sigPolicyStoreParams = new LinkedHashMap<>();
				sigPolicyStoreParams.put(JAdESHeaderParameterNames.SIG_POL_DOC,
						Utils.toBase64(DSSUtils.toByteArray(signaturePolicyStore.getSignaturePolicyContent())));

				SpDocSpecification spDocSpecification = signaturePolicyStore.getSpDocSpecification();
				JsonObject oidObject = DSSJsonUtils.getOidObject(spDocSpecification.getId(), spDocSpecification.getDescription(), 
						spDocSpecification.getDocumentationReferences());
				sigPolicyStoreParams.put(JAdESHeaderParameterNames.SP_DSPEC, oidObject);

				JAdESEtsiUHeader etsiUHeader = jadesSignature.getEtsiUHeader();
				etsiUHeader.addComponent(JAdESHeaderParameterNames.SIG_PST,
						sigPolicyStoreParams, base64UrlInstance);

			} else {
				LOG.warn("Signature policy's digest doesn't match the document {} for signature {}", expectedDigest, jadesSignature.getId());
			}
		} else {
			LOG.warn("No SignaturePolicyIdentifier '{}' found for a signature with id '{}'!",
					JAdESHeaderParameterNames.SIG_PID, jadesSignature.getId());
		}
	}

}
