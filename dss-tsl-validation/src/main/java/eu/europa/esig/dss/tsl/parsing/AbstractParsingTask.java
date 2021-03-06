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
package eu.europa.esig.dss.tsl.parsing;

import java.io.InputStream;
import java.math.BigInteger;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Objects;

import javax.xml.datatype.XMLGregorianCalendar;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.TrustedListFacade;
import eu.europa.esig.trustedlist.jaxb.tsl.NextUpdateType;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyURIListType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSLSchemeInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;

public abstract class AbstractParsingTask {

	private final DSSDocument document;

	protected AbstractParsingTask(DSSDocument document) {
		Objects.requireNonNull(document, "The document is null");
		this.document = document;
	}

	protected TrustStatusListType getJAXBObject() {
		try (InputStream is = document.openStream()) {
			return TrustedListFacade.newFacade().unmarshall(is);
		} catch (Exception e) {
			String message = "Unable to parse binaries. Reason : '%s'";
			// get complete error message in case if the message string is not defined directly
			if (e.getMessage() == null && e.getCause() != null) {
				throw new DSSException(String.format(message, e.getCause().getMessage()), e);
			}
			throw new DSSException(String.format(message, e.getMessage()), e);
		}
	}

	protected void commonParseSchemeInformation(AbstractParsingResult result, TSLSchemeInformationType schemeInformation) {

		extractSequenceNumber(result, schemeInformation);
		extractTerritory(result, schemeInformation);
		extractVersion(result, schemeInformation);
		extractIssueDate(result, schemeInformation);
		extractNextUpdateDate(result, schemeInformation);
		extractDistributionPoints(result, schemeInformation);

	}

	private void extractSequenceNumber(AbstractParsingResult result, TSLSchemeInformationType schemeInformation) {
		BigInteger tslSequenceNumber = schemeInformation.getTSLSequenceNumber();
		if (tslSequenceNumber != null) {
			result.setSequenceNumber(tslSequenceNumber.intValue());
		}
	}

	private void extractTerritory(AbstractParsingResult result, TSLSchemeInformationType schemeInformation) {
		result.setTerritory(schemeInformation.getSchemeTerritory());
	}

	private void extractVersion(AbstractParsingResult result, TSLSchemeInformationType schemeInformation) {
		BigInteger tslVersionIdentifier = schemeInformation.getTSLVersionIdentifier();
		if (tslVersionIdentifier != null) {
			result.setVersion(tslVersionIdentifier.intValue());
		}
	}

	private void extractIssueDate(AbstractParsingResult result, TSLSchemeInformationType schemeInformation) {
		result.setIssueDate(convertToDate(schemeInformation.getListIssueDateTime()));
	}

	private void extractNextUpdateDate(AbstractParsingResult result, TSLSchemeInformationType schemeInformation) {
		NextUpdateType nextUpdate = schemeInformation.getNextUpdate();
		if (nextUpdate != null) {
			result.setNextUpdateDate(convertToDate(nextUpdate.getDateTime()));
		}
	}

	private Date convertToDate(XMLGregorianCalendar gregorianCalendar) {
		if (gregorianCalendar != null) {
			GregorianCalendar toGregorianCalendar = gregorianCalendar.toGregorianCalendar();
			if (toGregorianCalendar != null) {
				return toGregorianCalendar.getTime();
			}
		}
		return null;
	}

	private void extractDistributionPoints(AbstractParsingResult result, TSLSchemeInformationType schemeInformation) {
		NonEmptyURIListType distributionPoints = schemeInformation.getDistributionPoints();
		if (distributionPoints != null && Utils.isCollectionNotEmpty(distributionPoints.getURI())) {
			result.setDistributionPoints(Collections.unmodifiableList(distributionPoints.getURI()));
		} else {
			result.setDistributionPoints(Collections.emptyList());
		}
	}

}
