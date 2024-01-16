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
package eu.europa.esig.dss.validation.scope;

import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Extracts evidence record scopes representing the covered archival data objects
 *
 */
public class EvidenceRecordScopeFinder {

    /** The associated evidence record */
    protected final EvidenceRecord evidenceRecord;

    /**
     * Default constructor
     *
     * @param evidenceRecord {@link EvidenceRecord}
     */
    public EvidenceRecordScopeFinder(final EvidenceRecord evidenceRecord) {
        Objects.requireNonNull(evidenceRecord, "EvidenceRecord shall be provided!");
        this.evidenceRecord = evidenceRecord;
    }

    /**
     * This method returns an evidence record scope for the given {@code EvidenceRecord}
     *
     * @return a list of {@link SignatureScope}s
     */
    public List<SignatureScope> findEvidenceRecordScope() {
        return findEvidenceRecordScope(evidenceRecord.getReferenceValidation());
    }

    /**
     * Extracts evidence record scopes for the provided list of reference validation and detached content
     *
     * @param referenceValidations a list of {@link ReferenceValidation}s
     * @return a list of {@link SignatureScope}s
     */
    protected List<SignatureScope> findEvidenceRecordScope(List<ReferenceValidation> referenceValidations) {
        final List<SignatureScope> signatureScopes = new ArrayList<>();

        List<DSSDocument> detachedContents = evidenceRecord.getDetachedContents();

        List<DSSDocument> coveredDocuments = new ArrayList<>();
        for (ReferenceValidation referenceValidation : referenceValidations) {
            if (referenceValidation.isFound()) {
                if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT.equals(referenceValidation.getType())) {
                    DSSDocument detachedDocument;
                    if (Utils.collectionSize(detachedContents) == 1) {
                        detachedDocument = detachedContents.iterator().next();
                    } else {
                        detachedDocument = getDetachedDocument(referenceValidation, detachedContents);
                    }
                    if (detachedDocument != null && !coveredDocuments.contains(detachedDocument)) {
                        signatureScopes.add(new FullSignatureScope(detachedDocument.getName() != null ?
                                detachedDocument.getName() : "Full document", detachedDocument));
                        coveredDocuments.add(detachedDocument); // do not add documents with the same digests
                    }
                }
            }
        }

        return signatureScopes;
    }

    private DSSDocument getDetachedDocument(ReferenceValidation referenceValidation, List<DSSDocument> detachedDocuments) {
        for (DSSDocument document : detachedDocuments) {
            Objects.requireNonNull(document.getName(), "Name shall be defined when multiple documents provided!");
            if (referenceValidation.getName().equals(document.getName())) {
                return document;
            }
        }
        return null;
    }

}
