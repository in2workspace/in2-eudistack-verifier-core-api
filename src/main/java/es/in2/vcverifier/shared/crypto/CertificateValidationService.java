package es.in2.vcverifier.shared.crypto;

import java.util.Map;

public interface CertificateValidationService {
    void extractAndVerifyCertificate(String verifiableCredential, Map<String, Object> vcHeader, String expectedOrgId);
}
