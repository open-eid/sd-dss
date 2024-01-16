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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * The common implementation of {@code X509URLCertificateSource} retrieving X.509 certificates by the given URI
 * 
 */
public class CommonX509URLCertificateSource extends CommonCertificateSource implements X509URLCertificateSource {

    private static final long serialVersionUID = 5423873125786850353L;

    private static final Logger LOG = LoggerFactory.getLogger(CommonX509URLCertificateSource.class);

    /** Map of uris and related certificate tokens */
    private Map<String, Collection<CertificateToken>> mapByUri = new HashMap<>();

    /**
     * Default constructor
     */
    public CommonX509URLCertificateSource() {
        // empty
    }

    @Override
    public CertificateToken addCertificate(CertificateToken certificateToAdd) {
        throw new UnsupportedOperationException("#addCertificate(certificateToAdd) method is not supported in CommonX509URLCertificateSource! " +
                "Please use #addCertificate(uri, certificateToAdd) or #addCertificates(uri, certificatesToAdd) methods.");
    }

    /**
     * Adds a certificate for a given 'x5u' URL (JWS/JAdES)
     *
     * @param uri         the used URI in the JWS/JAdES
     * @param certificate the related certificate token
     * @return the certificate
     */
    public CertificateToken addCertificate(String uri, CertificateToken certificate) {
        CertificateToken addedCertificate = super.addCertificate(certificate);
        Collection<CertificateToken> certificateTokens = mapByUri.get(uri);
        if (Utils.isCollectionEmpty(certificateTokens)) {
            certificateTokens = new ArrayList<>();
            mapByUri.put(uri, certificateTokens);
        } else if (LOG.isDebugEnabled()) {
            LOG.debug("URI {} is already known, the certificate will be added to the existing collection.", uri);
        }
        certificateTokens.add(certificate);
        return addedCertificate;
    }

    /**
     * Adds a collection of certificates for a given 'x5u' URL (JWS/JAdES)
     *
     * @param uri          the used URI in the JWS/JAdES
     * @param certificates a collection of {@link CertificateToken}s
     * @return the certificate
     */
    public Collection<CertificateToken> addCertificates(String uri, Collection<CertificateToken> certificates) {
        Collection<CertificateToken> certificateTokens = mapByUri.get(uri);
        if (Utils.isCollectionEmpty(certificateTokens)) {
            certificateTokens = new ArrayList<>();
            mapByUri.put(uri, certificateTokens);
        } else if (LOG.isDebugEnabled()) {
            LOG.debug("URI {} is already known, the certificates will be added to the existing collection.", uri);
        }
        for (CertificateToken certificate : certificates) {
            CertificateToken addedCertificate = super.addCertificate(certificate);
            certificateTokens.add(addedCertificate);
        }
        return certificateTokens;
    }

    @Override
    public Collection<CertificateToken> getCertificatesByUrl(String uri) {
        return mapByUri.get(uri);
    }

    @Override
    protected void reset() {
        super.reset();
        mapByUri = new HashMap<>();
    }
    
}
