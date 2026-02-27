package es.in2.vcverifier.verifier.domain.model.sdjwt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class DisclosureTest {

    @Test
    @DisplayName("parse valid disclosure and verify fields")
    void parse_validDisclosure_extractsFields() {
        // [salt, claimName, claimValue]
        String json = "[\"_26bc4LT-ac6q2KI6cBW5es\",\"family_name\",\"Möbius\"]";
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));

        Disclosure d = Disclosure.parse(encoded);

        assertEquals("_26bc4LT-ac6q2KI6cBW5es", d.salt());
        assertEquals("family_name", d.claimName());
        assertEquals("Möbius", d.claimValue());
        assertEquals(encoded, d.encoded());
    }

    @Test
    @DisplayName("digest is deterministic for the same encoded string")
    void digest_isDeterministic() {
        String json = "[\"salt1\",\"name\",\"Alice\"]";
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));

        Disclosure d = Disclosure.parse(encoded);

        assertEquals(d.digest(), d.digest());
    }

    @Test
    @DisplayName("different disclosures produce different digests")
    void digest_differentDisclosures_differentDigests() {
        String json1 = "[\"salt1\",\"name\",\"Alice\"]";
        String json2 = "[\"salt2\",\"name\",\"Bob\"]";
        String enc1 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json1.getBytes(StandardCharsets.UTF_8));
        String enc2 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json2.getBytes(StandardCharsets.UTF_8));

        Disclosure d1 = Disclosure.parse(enc1);
        Disclosure d2 = Disclosure.parse(enc2);

        assertNotEquals(d1.digest(), d2.digest());
    }

    @Test
    @DisplayName("parse throws on 2-element array")
    void parse_wrongElementCount_throws() {
        String json = "[\"salt\",\"name\"]";
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));

        assertThrows(IllegalArgumentException.class, () -> Disclosure.parse(encoded));
    }

    @Test
    @DisplayName("parse throws on invalid base64url")
    void parse_invalidBase64_throws() {
        assertThrows(IllegalArgumentException.class, () -> Disclosure.parse("!!!not-base64!!!"));
    }

    @Test
    @DisplayName("parse throws on null input")
    void parse_null_throws() {
        assertThrows(IllegalArgumentException.class, () -> Disclosure.parse(null));
    }

    @Test
    @DisplayName("parse throws on blank input")
    void parse_blank_throws() {
        assertThrows(IllegalArgumentException.class, () -> Disclosure.parse("  "));
    }

    @Test
    @DisplayName("digest with custom algorithm works")
    void digest_withCustomAlgorithm() {
        String json = "[\"salt\",\"name\",\"Alice\"]";
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));

        Disclosure d = Disclosure.parse(encoded);

        // SHA-256 should produce a non-empty string
        String sha256 = d.digest("SHA-256");
        assertNotNull(sha256);
        assertFalse(sha256.isBlank());

        // Unsupported algorithm should throw
        assertThrows(IllegalArgumentException.class, () -> d.digest("FAKE-ALG"));
    }

    @Test
    @DisplayName("parse handles object claim value")
    void parse_objectClaimValue() {
        String json = "[\"salt\",\"address\",{\"street\":\"123 Main St\"}]";
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));

        Disclosure d = Disclosure.parse(encoded);

        assertEquals("address", d.claimName());
        assertNotNull(d.claimValue());
    }
}
