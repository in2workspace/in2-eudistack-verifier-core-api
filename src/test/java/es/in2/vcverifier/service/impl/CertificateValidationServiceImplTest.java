package es.in2.vcverifier.service.impl;

import es.in2.vcverifier.exception.MismatchOrganizationIdentifierException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class CertificateValidationServiceImplTest {

    private CertificateValidationServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new CertificateValidationServiceImpl();
    }

    // --- x5c header validation ---

    @Test
    void extractAndVerifyCertificate_x5cNotAList_throwsIllegalArgument() {
        Map<String, Object> header = Map.of("x5c", "not-a-list");
        assertThrows(IllegalArgumentException.class,
                () -> service.extractAndVerifyCertificate("jwt", header, "orgId"));
    }

    @Test
    void extractAndVerifyCertificate_x5cMissing_throwsIllegalArgument() {
        Map<String, Object> header = Map.of();
        assertThrows(IllegalArgumentException.class,
                () -> service.extractAndVerifyCertificate("jwt", header, "orgId"));
    }

    @Test
    void extractAndVerifyCertificate_x5cNull_throwsIllegalArgument() {
        Map<String, Object> header = new HashMap<>();
        header.put("x5c", null);
        assertThrows(IllegalArgumentException.class,
                () -> service.extractAndVerifyCertificate("jwt", header, "orgId"));
    }

    @Test
    void extractAndVerifyCertificate_x5cEmptyList_throwsIllegalArgument() {
        Map<String, Object> header = Map.of("x5c", List.of());
        assertThrows(IllegalArgumentException.class,
                () -> service.extractAndVerifyCertificate("jwt", header, "orgId"));
    }

    @Test
    void extractAndVerifyCertificate_x5cWithNonStringEntries_doesNotThrow() {
        // Non-string entries hit 'continue', loop finishes normally without finding a match.
        List<Object> x5c = new ArrayList<>();
        x5c.add(42);
        Map<String, Object> header = new HashMap<>();
        header.put("x5c", x5c);

        // The loop hits continue for non-string, finishes, and no exception is thrown
        // (no processCertificate returning null means the throw-after-process path is not reached)
        assertDoesNotThrow(() -> service.extractAndVerifyCertificate("jwt", header, "orgId"));
    }

    @Test
    void extractAndVerifyCertificate_x5cWithInvalidBase64Cert_throwsMismatch() {
        // A string that decodes from base64 but is not a valid X.509 DER
        String invalidCert = Base64.getEncoder().encodeToString("this-is-not-a-certificate".getBytes());
        Map<String, Object> header = Map.of("x5c", List.of(invalidCert));

        // processCertificate catches CertificateException -> returns null -> throws MismatchOrganizationIdentifierException
        assertThrows(MismatchOrganizationIdentifierException.class,
                () -> service.extractAndVerifyCertificate("jwt", header, "orgId"));
    }

    @Test
    void extractAndVerifyCertificate_x5cWithGarbageBase64_throwsMismatch() {
        // Valid base64 but garbage bytes, CertificateFactory will reject it
        String garbageCert = Base64.getEncoder().encodeToString(new byte[]{0x30, 0x00});
        Map<String, Object> header = Map.of("x5c", List.of(garbageCert));

        assertThrows(MismatchOrganizationIdentifierException.class,
                () -> service.extractAndVerifyCertificate("jwt", header, "orgId"));
    }
}
