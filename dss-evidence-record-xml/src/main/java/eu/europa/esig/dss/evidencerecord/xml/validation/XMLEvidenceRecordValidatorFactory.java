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
package eu.europa.esig.dss.evidencerecord.xml.validation;


import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidator;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidatorFactory;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * Loads the relevant validator for an XML Evidence Record document validation
 *
 */
public class XMLEvidenceRecordValidatorFactory implements EvidenceRecordValidatorFactory {

    /**
     * Default constructor
     */
    public XMLEvidenceRecordValidatorFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        XMLEvidenceRecordValidator validator = new XMLEvidenceRecordValidator();
        return validator.isSupported(document);
    }

    @Override
    public EvidenceRecordValidator create(DSSDocument document) {
        return new XMLEvidenceRecordValidator(document);
    }

}
