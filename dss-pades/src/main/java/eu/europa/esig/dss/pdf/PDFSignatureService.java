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
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.PAdESCommonParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pades.validation.PdfValidationDataContainer;
import eu.europa.esig.dss.pdf.modifications.PdfDifferencesFinder;
import eu.europa.esig.dss.pdf.modifications.PdfObjectModificationsFinder;
import eu.europa.esig.dss.signature.resources.DSSResourcesHandlerBuilder;
import eu.europa.esig.dss.validation.AdvancedSignature;

import java.util.List;

/**
 * The usage of this interface permits the user to choose the underlying PDF library used to create PDF signatures.
 *
 */
public interface PDFSignatureService {
	
	/**
	 * Returns the digest value of a PDF document.
	 *
	 * @param toSignDocument
	 *            the document to be signed
	 * @param parameters
	 *            the signature/timestamp parameters
	 * @return the digest value
	 */
	byte[] digest(final DSSDocument toSignDocument, final PAdESCommonParameters parameters);

	/**
	 * Signs a PDF document
	 *
	 * @param toSignDocument
	 *            the pdf document to be signed
	 * @param cmsSignedData
	 *            the encoded CMS Signed data
	 * @param parameters
	 *            the signature/timestamp parameters
	 * @return {@link DSSDocument}
	 */
	DSSDocument sign(final DSSDocument toSignDocument, final byte[] cmsSignedData,
					 final PAdESCommonParameters parameters);

	/**
	 * Retrieves revisions from a PDF document
	 * 
	 * @param document
	 *            the document to extract revisions from
	 * @param pwd
	 *            the password protection phrase used to encrypt the PDF document
	 *            use 'null' value for not an encrypted document
	 * @return list of extracted {@link PdfRevision}s
	 */
	List<PdfRevision> getRevisions(final DSSDocument document, final String pwd);

	/**
	 * This method adds the DSS dictionary (Baseline-LT)
	 * 
	 * @param document
	 *            the document to be extended
	 * @param validationDataForInclusion
	 *            {@link PdfValidationDataContainer}
	 * @return the pdf document with the added dss dictionary
	 */
	DSSDocument addDssDictionary(final DSSDocument document, final PdfValidationDataContainer validationDataForInclusion);

	/**
	 * This method adds the DSS dictionary (Baseline-LT) to a password-protected document
	 * 
	 * @param document
	 *            the document to be extended
	 * @param validationDataForInclusion
	 *            {@link PdfValidationDataContainer}
	 * @param pwd
	 *            the password protection used to create the encrypted document (optional)
	 * @return the pdf document with the added dss dictionary
	 */
	DSSDocument addDssDictionary(final DSSDocument document, final PdfValidationDataContainer validationDataForInclusion,
								 final String pwd);

	/**
	 * This method returns not signed signature-fields
	 * 
	 * @param document
	 *            the pdf document
	 * @return the list of empty signature fields
	 */
	List<String> getAvailableSignatureFields(final DSSDocument document);
	
	/**
	 * Returns not-signed signature fields from an encrypted document
	 * 
	 * @param document
	 *            the pdf document
	 * @param pwd
	 *            the password protection phrase used to encrypt the document
	 * @return the list of not signed signature field names
	 */
	List<String> getAvailableSignatureFields(final DSSDocument document, final String pwd);

	/**
	 * This method allows to add a new signature field to an existing pdf document
	 * 
	 * @param document
	 *            the pdf document
	 * @param parameters
	 *            the parameters with the coordinates,... of the signature field
	 * @return the pdf document with the new added signature field
	 */
	DSSDocument addNewSignatureField(final DSSDocument document, final SignatureFieldParameters parameters);

	/**
	 * This method allows to add a new signature field to an existing encrypted pdf document
	 * 
	 * @param document
	 *            the pdf document
	 * @param parameters
	 *            the parameters with the coordinates,... of the signature field
	 * @param pwd
	 *            the password protection used to create the encrypted document (optional)
	 * @return the pdf document with the new added signature field
	 */
	DSSDocument addNewSignatureField(final DSSDocument document, final SignatureFieldParameters parameters,
									 final String pwd);

	/**
	 * Analyze the PDF revision and try to detect any modification (shadow attacks)
	 *
	 * @param document {@link DSSDocument} the document
	 * @param signatures       the different signatures to analyse
	 * @param pwd                 {@link String} password protection
	 */
	void analyzePdfModifications(DSSDocument document, List<AdvancedSignature> signatures, String pwd);

	/**
	 * Returns a page preview with the visual signature
	 *
	 * @param toSignDocument
	 *            the document to be signed
	 * @param parameters
	 *            the signature/timestamp parameters
	 * @return a DSSDocument with the PNG picture
	 */
	DSSDocument previewPageWithVisualSignature(final DSSDocument toSignDocument, final PAdESCommonParameters parameters);

	/**
	 * Returns a preview of the signature field
	 *
	 * @param toSignDocument
	 *            the document to be signed
	 * @param parameters
	 *            the signature/timestamp parameters
	 * @return a DSSDocument with the PNG picture
	 */
	DSSDocument previewSignatureField(final DSSDocument toSignDocument, final PAdESCommonParameters parameters);

	/**
	 * Sets {@code DSSResourcesFactoryBuilder} to be used for a {@code DSSResourcesHandler}
	 * creation in internal methods. {@code DSSResourcesHandler} defines a way to operate with OutputStreams and
	 * create {@code DSSDocument}s.
	 *
	 * Default : {@code eu.europa.esig.dss.signature.resources.InMemoryResourcesHandler}. Works with data in memory.
	 *
	 * @param resourcesHandlerBuilder {@link DSSResourcesHandlerBuilder}
	 */
	void setResourcesHandlerBuilder(DSSResourcesHandlerBuilder resourcesHandlerBuilder);

	/**
	 * Sets the {@code PdfDifferencesFinder} used to find the differences on pages between given PDF revisions.
	 *
	 * Default : {@code eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder}
	 *
	 * @param pdfDifferencesFinder {@link PdfDifferencesFinder}
	 */
	void setPdfDifferencesFinder(PdfDifferencesFinder pdfDifferencesFinder);

	/**
	 * Sets the {@code PdfObjectModificationsFinder} used to find the differences between internal PDF objects occurred
	 * between given PDF revisions.
	 *
	 * Default : {@code eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder}
	 *
	 * @param pdfObjectModificationsFinder {@link PdfObjectModificationsFinder}
	 */
	void setPdfObjectModificationsFinder(PdfObjectModificationsFinder pdfObjectModificationsFinder);

}
