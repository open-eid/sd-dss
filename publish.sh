#!/bin/bash

version="5.2.d4j.4"
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
for submodule in dss-common-validation-jaxb dss-detailed-report-jaxb dss-diagnostic-jaxb dss-document dss-model dss-policy-jaxb dss-reports dss-service dss-simple-report-jaxb dss-spi dss-token dss-tsl-jaxb dss-tsl-validation dss-xades validation-policy dss-pades dss-cades dss-utils dss-soap dss-utils-apache-commons dss-rest-client dss-server-signing-common dss-asic-xades dss-crl-parser-stream dss-server-signing-soap dss-asic-common dss-utils-google-guava dss-rest dss-test dss-crl-parser dss-cookbook dss-server-signing-rest dss-validation-rest dss-soap-client dss-validation-rest-client sscd-mocca-adapter dss-validation-soap-client dss-remote-services dss-asic-cades dss-validation-soap
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
