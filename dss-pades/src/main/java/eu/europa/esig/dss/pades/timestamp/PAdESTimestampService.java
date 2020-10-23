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
package eu.europa.esig.dss.pades.timestamp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class PAdESTimestampService {

	private final TSPSource tspSource;
	private final PDFSignatureService pdfSignatureService;

	public PAdESTimestampService(TSPSource tspSource, PDFSignatureService pdfSignatureService) {
		this.tspSource = tspSource;
		this.pdfSignatureService = pdfSignatureService;
	}
	
	public DSSDocument timestampDocument(final DSSDocument document, final PAdESTimestampParameters params) throws DSSException {
		final DigestAlgorithm timestampDigestAlgorithm = params.getDigestAlgorithm();
		final byte[] digest = pdfSignatureService.digest(document, params);
		final TimestampBinary timeStampToken = tspSource.getTimeStampResponse(timestampDigestAlgorithm, digest);
		final byte[] encoded = DSSASN1Utils.getDEREncoded(timeStampToken);
		return pdfSignatureService.sign(document, encoded, params);
	}

}
