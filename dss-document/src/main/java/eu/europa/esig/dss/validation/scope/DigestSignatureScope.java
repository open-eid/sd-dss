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

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.model.scope.SignatureScope;

/**
 * The Signature Scope defines a Digest document
 *
 */
public class DigestSignatureScope extends SignatureScope {

	private static final long serialVersionUID = -5483258316745203622L;

	/**
	 * Default constructor with a filename
	 *
	 * @param filename {@link String} filename
	 * @param digestDocument {@link String} filename
	 */
	public DigestSignatureScope(final String filename, DSSDocument digestDocument) {
		super(filename, digestDocument);
	}

    @Override
    public String getDescription(TokenIdentifierProvider tokenIdentifierProvider) {
        return "Digest of the document content";
    }

	@Override
	public SignatureScopeType getType() {
		return SignatureScopeType.DIGEST;
	}

}
