#!/bin/bash

version="6.0.1.d4j.1"
staging_url="https://oss.sonatype.org/service/local/staging/deploy/maven2/"
#staging_url=file:/Users/rainer/tmp/test-local-repo
repositoryId="ossrh"

# Starting GPG agent to store GPG passphrase so we wouldn't have to enter the passphrase every time
eval $(gpg-agent --daemon --no-grab)
export GPG_TTY=$(tty)
export GPG_AGENT_INFO

# Deploy parent POM
mvn gpg:sign-and-deploy-file -DpomFile=pom.xml -Dfile=pom.xml -Durl=$staging_url -DrepositoryId=$repositoryId

# Deploy each sub module artifacts
for submodule in dss-alert dss-asic-cades dss-asic-common dss-asic-xades dss-bom dss-cades dss-certificate-validation-common dss-certificate-validation-dto dss-certificate-validation-rest dss-certificate-validation-rest-client dss-certificate-validation-soap dss-certificate-validation-soap-client dss-common-remote-converter dss-common-remote-dto dss-cookbook dss-crl-parser dss-crl-parser-stream dss-crl-parser-x509crl dss-detailed-report-jaxb dss-diagnostic-jaxb dss-document dss-enumerations dss-evidence-record-common dss-evidence-record-xml dss-i18n dss-jacoco-coverage dss-jades dss-jaxb-common dss-jaxb-parsers dss-model dss-pades dss-pades-openpdf dss-pades-pdfbox dss-pdfa dss-pki-factory dss-pki-factory-jaxb dss-policy-jaxb dss-server-signing-common dss-server-signing-dto dss-server-signing-rest dss-server-signing-rest-client dss-server-signing-soap dss-server-signing-soap-client dss-service dss-signature-dto dss-signature-remote dss-signature-rest dss-signature-rest-client dss-signature-soap dss-signature-soap-client dss-simple-certificate-report-jaxb dss-simple-report-jaxb dss-spi dss-test dss-timestamp-dto dss-timestamp-remote dss-timestamp-remote-rest dss-timestamp-remote-rest-client dss-timestamp-remote-soap dss-timestamp-remote-soap-client dss-token dss-tsl-validation dss-utils dss-utils-apache-commons dss-utils-google-guava dss-validation-dto dss-validation-rest dss-validation-rest-client dss-validation-server-common dss-validation-soap dss-validation-soap-client dss-xades dss-xml-common dss-xml-utils specs-asic-manifest specs-jades specs-jws specs-saml-assertion specs-trusted-list specs-validation-report specs-xades specs-xmldsig specs-xmlers validation-policy
do
	echo "Deploying submodule $submodule"
    cd $submodule
    artifact="target/$submodule-$version"
    mvn gpg:sign-and-deploy-file -DpomFile=pom.xml -Dfile=$artifact.jar -Durl=$staging_url -DrepositoryId=$repositoryId
    mvn gpg:sign-and-deploy-file -DpomFile=pom.xml -Dfile=$artifact-sources.jar -Dclassifier=sources -Durl=$staging_url -DrepositoryId=$repositoryId
    mvn gpg:sign-and-deploy-file -DpomFile=pom.xml -Dfile=$artifact-javadoc.jar -Dclassifier=javadoc -Durl=$staging_url -DrepositoryId=$repositoryId
    cd ..
    echo "Finished $submodule deployment"
done

killall gpg-agent
