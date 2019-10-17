package eu.europa.esig.dss.asic;

import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

public class AsicWithXadesSignatureRemove {

  @Test
  public void removeSignature() throws IOException {
    DSSDocument asicContainer = new FileDocument("src/test/resources/ASiCEWith2Signatures.bdoc");

    CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
    ASiCWithXAdESService aSiCWithXAdESService = new ASiCWithXAdESService(certificateVerifier);

    DSSDocument containerWOSignature = aSiCWithXAdESService.removeSignatureById(asicContainer, "S0");
    try (ZipInputStream zis = new ZipInputStream(containerWOSignature.openStream());){
      ZipEntry entry;
      int sigCount = 0;
      while ((entry = zis.getNextEntry()) != null) {
        final String name = entry.getName();
        if (name.contains("signature")) {
          sigCount ++;
        }
      }
      Assert.assertEquals(1, sigCount);
    }
  }
}
