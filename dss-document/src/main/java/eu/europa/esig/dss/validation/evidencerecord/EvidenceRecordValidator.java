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
package eu.europa.esig.dss.validation.evidencerecord;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Abstract class containing the basic logic for an Evidence Record validation,
 * as well as containing a loader for an Evidence Record validation of the given format.
 *
 */
public abstract class EvidenceRecordValidator extends SignedDocumentValidator {

    /** Cached instance of evidence record */
    private EvidenceRecord evidenceRecord;

    /**
     * Empty constructor
     */
    protected EvidenceRecordValidator() {
        // empty
    }

    /**
     * Instantiates the class with a document to be validated
     *
     * @param document {@link DSSDocument} to be validated
     */
    protected EvidenceRecordValidator(DSSDocument document) {
        Objects.requireNonNull(document, "Document to be validated cannot be null!");
        this.document = document;
    }

    /**
     * This method guesses the document format and returns an appropriate
     * evidence record validator.
     *
     * @param dssDocument
     *            The instance of {@code DSSDocument} to validate
     * @return returns the specific instance of {@link EvidenceRecordValidator} in terms of the document type
     */
    public static EvidenceRecordValidator fromDocument(final DSSDocument dssDocument) {
        return EvidenceRecordValidatorFactory.fromDocument(dssDocument);
    }

    /**
     * Returns an evidence record extracted from the document
     *
     * @return {@link EvidenceRecord}
     */
    public EvidenceRecord getEvidenceRecord() {
        if (evidenceRecord == null) {
            evidenceRecord = buildEvidenceRecord();

            List<SignatureScope> evidenceRecordScopes = getEvidenceRecordScopes(evidenceRecord);
            evidenceRecord.setEvidenceRecordScopes(evidenceRecordScopes);
            evidenceRecord.setTimestampedReferences(getTimestampedReferences(evidenceRecordScopes));
        }
        return evidenceRecord;
    }

    /**
     * Builds an evidence record object
     *
     * @return {@link EvidenceRecord}
     */
    protected abstract EvidenceRecord buildEvidenceRecord();

    @Override
    public List<EvidenceRecord> getDetachedEvidenceRecords() {
        return Collections.singletonList(getEvidenceRecord());
    }

    @Override
    public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
        throw new UnsupportedOperationException("getOriginalDocuments(AdvancedSignature) is " +
                "not supported for EvidenceRecordValidator!");
    }

}
