package org.example;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.internal.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

public class Main {
    public static void main(String[] args) throws Exception {
        FileInputStream fis = new FileInputStream("file.cms");
        byte[] cmsBytes = fis.readAllBytes();
        fis.close();

        CMSSignedData cmsSignedData = new CMSSignedData(cmsBytes);

        SignerInformationStore signerInfoStore = cmsSignedData.getSignerInfos();
        Collection<SignerInformation> signerInfos = signerInfoStore.getSigners();

        Store<X509CertificateHolder> certStore = cmsSignedData.getCertificates();
        Collection<X509CertificateHolder> certificates = certStore.getMatches(null);

        for (SignerInformation signerInfo : signerInfos) {
            X509CertificateHolder certificate = certificates.stream()
                    .filter(cert -> cert.getSerialNumber().equals(signerInfo.getSID().getSerialNumber()))
                    .findFirst()
                    .orElseThrow(() -> new Exception("Certificate not found"));
            if (signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certificate))) {
                System.out.println(certificate.getSubject());
                System.out.println(certificate.toASN1Structure().toASN1Primitive());
            } else {
                System.out.println("Signature is not valid");
            }
        }

    }
}