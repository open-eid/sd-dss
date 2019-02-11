package eu.europa.esig.dss.client.http.commons;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * Accepts all certificates.
 * TODO: Remove once SSL context is forced
 * @see <a href="https://github.com/esig/dss/commit/3bf3cffeda6e44a1ed17297caf06aac34fc15704#diff-dd0604e08dcdb1b89e09016e4424f667">https://github.com/esig/dss/commit/3bf3cffeda6e44a1ed17297caf06aac34fc15704#diff-dd0604e08dcdb1b89e09016e4424f667</a>
 *
 * @author lodermatt
 */
public class AcceptAllTrustManager implements X509TrustManager {

    /**
     * Constructor.
     */
    public AcceptAllTrustManager() {
        super();
        // Do nothing
    }

    /*
     * (non-Javadoc)
     *
     * @see javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String)
     */
    @Override
    public void checkClientTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
    }

    /*
     * (non-Javadoc)
     *
     * @see javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String)
     */
    @Override
    public void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
    }

    /*
     * (non-Javadoc)
     *
     * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }

}
