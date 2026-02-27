package es.in2.vcverifier.model.sdjwt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class SdJwtTest {

    private static final String DUMMY_JWT = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSJ9.AAAA";

    @Test
    @DisplayName("parse SD-JWT with disclosures and KB-JWT")
    void parse_withDisclosuresAndKbJwt() {
        String disc1 = makeDisclosure("salt1", "given_name", "Alice");
        String disc2 = makeDisclosure("salt2", "family_name", "Smith");
        String kbJwt = "eyJhbGciOiJFUzI1NiJ9.eyJub25jZSI6InRlc3QifQ.BBBB";
        String combined = DUMMY_JWT + "~" + disc1 + "~" + disc2 + "~" + kbJwt;

        SdJwt sdJwt = SdJwt.parse(combined);

        assertEquals(DUMMY_JWT, sdJwt.issuerJwt());
        assertEquals(2, sdJwt.disclosures().size());
        assertEquals("given_name", sdJwt.disclosures().get(0).claimName());
        assertEquals("family_name", sdJwt.disclosures().get(1).claimName());
        assertEquals(kbJwt, sdJwt.keyBindingJwt());
    }

    @Test
    @DisplayName("parse SD-JWT without KB-JWT (trailing ~)")
    void parse_withoutKbJwt() {
        String disc = makeDisclosure("salt", "name", "Bob");
        String combined = DUMMY_JWT + "~" + disc + "~";

        SdJwt sdJwt = SdJwt.parse(combined);

        assertEquals(DUMMY_JWT, sdJwt.issuerJwt());
        assertEquals(1, sdJwt.disclosures().size());
        assertNull(sdJwt.keyBindingJwt());
    }

    @Test
    @DisplayName("parse SD-JWT with no disclosures and no KB-JWT")
    void parse_noDisclosuresNoKbJwt() {
        String combined = DUMMY_JWT + "~";

        SdJwt sdJwt = SdJwt.parse(combined);

        assertEquals(DUMMY_JWT, sdJwt.issuerJwt());
        assertTrue(sdJwt.disclosures().isEmpty());
        assertNull(sdJwt.keyBindingJwt());
    }

    @Test
    @DisplayName("serialize round-trip preserves structure")
    void serialize_roundTrip() {
        String disc1 = makeDisclosure("salt1", "name", "Alice");
        String disc2 = makeDisclosure("salt2", "email", "alice@example.com");
        String kbJwt = "eyJhbGciOiJFUzI1NiJ9.eyJub25jZSI6InRlc3QifQ.CCCC";
        String combined = DUMMY_JWT + "~" + disc1 + "~" + disc2 + "~" + kbJwt;

        SdJwt parsed = SdJwt.parse(combined);
        String serialized = parsed.serialize();
        SdJwt reparsed = SdJwt.parse(serialized);

        assertEquals(parsed.issuerJwt(), reparsed.issuerJwt());
        assertEquals(parsed.disclosures().size(), reparsed.disclosures().size());
        assertEquals(parsed.keyBindingJwt(), reparsed.keyBindingJwt());
    }

    @Test
    @DisplayName("serialize without KB-JWT ends with ~")
    void serialize_withoutKbJwt_endsWithTilde() {
        String disc = makeDisclosure("salt", "name", "Charlie");
        String combined = DUMMY_JWT + "~" + disc + "~";

        SdJwt sdJwt = SdJwt.parse(combined);
        String serialized = sdJwt.serialize();

        assertTrue(serialized.endsWith("~"));
        assertFalse(serialized.endsWith("~~"));
    }

    @Test
    @DisplayName("parse throws on null input")
    void parse_null_throws() {
        assertThrows(IllegalArgumentException.class, () -> SdJwt.parse(null));
    }

    @Test
    @DisplayName("parse throws on blank input")
    void parse_blank_throws() {
        assertThrows(IllegalArgumentException.class, () -> SdJwt.parse("  "));
    }

    @Test
    @DisplayName("parse throws on string without tilde separator")
    void parse_noTilde_throws() {
        assertThrows(IllegalArgumentException.class, () -> SdJwt.parse(DUMMY_JWT));
    }

    @Test
    @DisplayName("parse throws when issuer JWT is empty")
    void parse_emptyIssuerJwt_throws() {
        assertThrows(IllegalArgumentException.class, () -> SdJwt.parse("~disc1~"));
    }

    @Test
    @DisplayName("computeSdHash returns non-empty base64url string")
    void computeSdHash_returnsNonEmpty() {
        String disc = makeDisclosure("salt", "name", "Alice");
        String combined = DUMMY_JWT + "~" + disc + "~";

        SdJwt sdJwt = SdJwt.parse(combined);
        String sdHash = sdJwt.computeSdHash();

        assertNotNull(sdHash);
        assertFalse(sdHash.isBlank());
        // Base64url has no padding
        assertFalse(sdHash.contains("="));
    }

    @Test
    @DisplayName("computeSdHash is deterministic")
    void computeSdHash_isDeterministic() {
        String disc = makeDisclosure("salt", "name", "Alice");
        String combined = DUMMY_JWT + "~" + disc + "~";

        SdJwt sdJwt = SdJwt.parse(combined);

        assertEquals(sdJwt.computeSdHash(), sdJwt.computeSdHash());
    }

    private String makeDisclosure(String salt, String claimName, Object claimValue) {
        String json = "[\"" + salt + "\",\"" + claimName + "\",\"" + claimValue + "\"]";
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
