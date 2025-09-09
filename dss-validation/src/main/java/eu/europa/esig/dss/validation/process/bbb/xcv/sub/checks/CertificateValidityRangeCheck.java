/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;
import java.util.stream.Stream;

/**
 * Checks if the certificate is not expired
 *
 * @param <T> implementation of the block's conclusion
 */
public class CertificateValidityRangeCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** Validation date */
	private final Date currentTime;

	/** Certificate to check */
	private final CertificateWrapper certificate;

	/** The certificate's revocation */
	private final CertificateRevocationWrapper usedCertificateRevocation;

	/** Defines whether revocation data is required for the certificate */
	private final boolean revocationDataRequired;

	/** Defines whether the revocation data's issuer is trusted */
	private final boolean revocationIssuerTrusted;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param certificate {@link CertificateWrapper}
	 * @param usedCertificateRevocation {@link CertificateRevocationWrapper}
	 * @param revocationDataRequired whether a revocation data is required for the given certificate
	 * @param revocationIssuerTrusted whether the revocation issuer is trusted, when applicable
	 * @param currentTime {@link Date} validation time
	 * @param constraint {@link LevelConstraint}
	 */
	public CertificateValidityRangeCheck(I18nProvider i18nProvider, T result, CertificateWrapper certificate,
										 CertificateRevocationWrapper usedCertificateRevocation, boolean revocationDataRequired,
										 boolean revocationIssuerTrusted, Date currentTime, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.currentTime = currentTime;
		this.certificate = certificate;
		this.usedCertificateRevocation = usedCertificateRevocation;
		this.revocationDataRequired = revocationDataRequired;
		this.revocationIssuerTrusted = revocationIssuerTrusted;
	}

	@Override
	protected boolean process() {
		return isInValidityRange(certificate);
	}

	private boolean isInValidityRange(CertificateWrapper certificateWrapper) {
		if (certificateWrapper != null) {
			Date notBefore = certificateWrapper.getNotBefore();
			Date notAfter = certificateWrapper.getNotAfter();
			return (notBefore != null && (currentTime.compareTo(notBefore) >= 0)) && (notAfter != null && (currentTime.compareTo(notAfter) <= 0));
		}
		return false;
	}

	private boolean isRevocationDataValid() {
		// other checks are performed before
		return revocationIssuerTrusted || isInValidityRange(usedCertificateRevocation.getSigningCertificate());
	}

	private boolean hasValidityBegun(CertificateWrapper certificateWrapper) {
		if (certificateWrapper != null) {
			Date notBefore = certificateWrapper.getNotBefore();
			return notBefore != null && currentTime.compareTo(notBefore) >= 0;
		}
		return false;
	}

	private boolean isSigningCertificateWithValidIssuer() {
		return isSigningCertificate(certificate) && isCertificateValid(certificate.getSigningCertificate());
	}

	private static boolean isSigningCertificate(CertificateWrapper certificateWrapper) {
		// DD4J-1302: Consider a certificate as signing certificate if the following conditions are met:
		// - The certificate has no BasicConstraints extension, or its CA attribute is false
		// - The certificate has KeyUsage extension with nonRepudiation bit set
		// - The certificate has no ExtendedKeyUsage extension, or it does not contain OCSPSigning nor timeStamping entries
		if (!certificateWrapper.isCA() && certificateWrapper.getKeyUsages().contains(KeyUsageBit.NON_REPUDIATION)) {
			return certificateWrapper.getExtendedKeyUsages().stream()
					.map(XmlOID::getValue)
					.noneMatch(oid -> Stream
							.of(ExtendedKeyUsage.OCSP_SIGNING, ExtendedKeyUsage.TIMESTAMPING)
							.anyMatch(eku -> eku.getOid().equals(oid))
					);
		}
		return false;
	}

	private boolean isCertificateValid(CertificateWrapper certificateWrapper) {
		if (certificateWrapper != null) {
			return isTrustAnchor(certificateWrapper) || isInValidityRange(certificateWrapper);
		}
		return false;
	}

	private boolean isTrustAnchor(CertificateWrapper certificateWrapper) {
		LevelConstraint failLevelConstraint = new LevelConstraint();
		failLevelConstraint.setLevel(Level.FAIL);

		return ValidationProcessUtils.isTrustAnchor(certificateWrapper, currentTime, failLevelConstraint);
	}

	@Override
	protected String buildAdditionalInfo() {
		String notBeforeStr = certificate.getNotBefore() == null ? " ? " : ValidationProcessUtils.getFormattedDate(certificate.getNotBefore());
		String notAfterStr = certificate.getNotAfter() == null ? " ? " : ValidationProcessUtils.getFormattedDate(certificate.getNotAfter());
		String validationTime = ValidationProcessUtils.getFormattedDate(currentTime);
		return i18nProvider.getMessage(MessageTag.CERTIFICATE_VALIDITY, validationTime, notBeforeStr, notAfterStr);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_ICTIVRSC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_ICTIVRSC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		boolean certificateIsKnownToNotBeRevoked = usedCertificateRevocation != null
				&& !usedCertificateRevocation.isRevoked() && (isRevocationDataValid()
				// DD4J-1302: Alternatively consider the certificate not revoked if the following conditions are met:
				// - The validity of the revocation certificate has begun (notBefore is not after the reference time)
				// - The certificate represents a signing certificate with a valid issuer
				|| (hasValidityBegun(usedCertificateRevocation.getSigningCertificate()) && isSigningCertificateWithValidIssuer())
		);
		if (!revocationDataRequired || certificateIsKnownToNotBeRevoked) {
			return SubIndication.OUT_OF_BOUNDS_NOT_REVOKED;
		}
		return SubIndication.OUT_OF_BOUNDS_NO_POE;
	}

}
