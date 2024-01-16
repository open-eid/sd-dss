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
import eu.europa.esig.dss.validation.DocumentValidatorFactory;

import java.util.Objects;
import java.util.ServiceLoader;

/**
 * This interface defines the factory to create a {@link EvidenceRecordValidator} for
 * a given {@link DSSDocument}
 */
public interface EvidenceRecordValidatorFactory extends DocumentValidatorFactory {

    /**
     * This method tests if the current implementation of {@link EvidenceRecordValidator}
     * supports the given document
     *
     * @param document
     *                 the document to be tested
     * @return true, if the {@link EvidenceRecordValidator} supports the given document
     */
    boolean isSupported(DSSDocument document);

    /**
     * This method instantiates a {@link EvidenceRecordValidator} with the given document
     *
     * @param document
     *                 the document to be used for the {@link EvidenceRecordValidator}
     *                 creation
     * @return an instance of {@link EvidenceRecordValidator} with the document
     */
    EvidenceRecordValidator create(DSSDocument document);

    /**
     * Verifies if the {@code document} is supported by one of the implementations,
     * across {@code EvidenceRecordValidatorFactory} instances found by ServiceLoader.
     *
     * @param document {@link DSSDocument} to verify
     * @return TRUE if the evidence record is supported by one of the found implementations, FALSE otherwise
     */
    static boolean isSupportedDocument(DSSDocument document) {
        Objects.requireNonNull(document, "DSSDocument is null");
        ServiceLoader<EvidenceRecordValidatorFactory> serviceLoaders = ServiceLoader.load(EvidenceRecordValidatorFactory.class);
        for (EvidenceRecordValidatorFactory factory : serviceLoaders) {
            if (factory.isSupported(document)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Creates an {@code EvidenceRecordValidator} by loading a corresponding implementation,
     * across {@code EvidenceRecordValidatorFactory} instances found by ServiceLoader.
     *
     * @param document {@link DSSDocument} to load validator for
     * @return {@link EvidenceRecordValidator} if corresponding implementation found
     * @throws UnsupportedOperationException is the document format is not supported or implementation is not found
     */
    static EvidenceRecordValidator fromDocument(DSSDocument document) throws UnsupportedOperationException {
        Objects.requireNonNull(document, "DSSDocument is null");
        ServiceLoader<EvidenceRecordValidatorFactory> serviceLoaders = ServiceLoader.load(EvidenceRecordValidatorFactory.class);
        for (EvidenceRecordValidatorFactory factory : serviceLoaders) {
            if (factory.isSupported(document)) {
                return factory.create(document);
            }
        }
        throw new UnsupportedOperationException("Document format not recognized/handled");
    }

}
