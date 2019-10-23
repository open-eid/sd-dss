#!/bin/bash

version="5.5.d4j.1"
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
for submodule in dss-asic-cades dss-asic-common dss-asic-xades dss-cades dss-certificate-validation-common dss-certificate-validation-dto dss-certificate-validation-rest-client dss-certificate-validation-rest dss-certificate-validation-soap-client dss-certificate-validation-soap dss-common-remote-converter dss-common-remote-dto dss-cookbook dss-crl-parser-stream dss-crl-parser-x509crl dss-crl-parser dss-detailed-report-jaxb dss-diagnostic-jaxb dss-document dss-enumerations dss-jaxb-parsers dss-model dss-pades-openpdf dss-pades-pdfbox dss-pades dss-policy-jaxb dss-server-signing-common dss-server-signing-dto dss-server-signing-rest-client dss-server-signing-rest dss-server-signing-soap-client dss-server-signing-soap dss-service dss-signature-dto dss-signature-remote dss-signature-rest-client dss-signature-rest dss-signature-soap-client dss-signature-soap dss-simple-certificate-report-jaxb dss-simple-report-jaxb dss-spi dss-test dss-token dss-tsl-validation dss-utils-apache-commons dss-utils-google-guava dss-utils dss-validation-dto dss-validation-rest-client dss-validation-rest dss-validation-server-common dss-validation-soap-client dss-validation-soap dss-xades specs-trusted-list specs-validation-report specs-xades specs-xmldsig validation-policy
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
