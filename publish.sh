#!/bin/bash

version="5.4.d4j.1"
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
for submodule in dss-asic-cades dss-asic-common dss-asic-xades dss-cades dss-common-validation-jaxb dss-cookbook dss-crl-parser dss-crl-parser-stream dss-crl-parser-x509crl dss-detailed-report-jaxb dss-diagnostic-jaxb dss-document dss-model dss-pades dss-pades-openpdf dss-pades-pdfbox dss-policy-jaxb dss-remote-services dss-reports dss-rest dss-rest-client dss-server-signing-common dss-server-signing-rest dss-server-signing-rest-client dss-server-signing-soap dss-server-signing-soap-client dss-service dss-simple-certificate-report-jaxb dss-simple-report-jaxb dss-soap dss-soap-client dss-spi dss-test dss-token dss-tsl-jaxb dss-tsl-validation dss-utils dss-utils-apache-commons dss-utils-google-guava dss-validation-rest dss-validation-rest-client dss-validation-soap dss-validation-soap-client dss-xades sscd-mocca-adapter validation-policy
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
