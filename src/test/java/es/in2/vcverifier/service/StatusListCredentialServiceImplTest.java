package es.in2.vcverifier.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.exception.StatusListCredentialException;
import es.in2.vcverifier.model.StatusListCredentialData;
import es.in2.vcverifier.service.impl.StatusListCredentialServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class StatusListCredentialServiceImplTest {

    private StatusListCredentialServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new StatusListCredentialServiceImpl(new ObjectMapper());
    }

    // ------------------------------------------------------------------------
    // validateStatusPurposeMatches
    // ------------------------------------------------------------------------

    @Test
    void validateStatusPurposeMatches_whenExpectedBlank_throws() {
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.validateStatusPurposeMatches("revocation", "  ")
        );
        assertEquals("Expected statusPurpose cannot be blank", ex.getMessage());
    }

    @Test
    void validateStatusPurposeMatches_whenActualBlank_throws() {
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.validateStatusPurposeMatches(" ", "revocation")
        );
        assertEquals("Status List Credential statusPurpose can't be blank", ex.getMessage());
    }

    @Test
    void validateStatusPurposeMatches_whenMismatch_throws() {
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.validateStatusPurposeMatches("suspension", "revocation")
        );
        assertEquals("StatusPurpose mismatch. expected=revocation, actual=suspension", ex.getMessage());
    }

    @Test
    void validateStatusPurposeMatches_whenMatch_doesNotThrow() {
        assertDoesNotThrow(() -> service.validateStatusPurposeMatches("revocation", "revocation"));
    }

    // ------------------------------------------------------------------------
    // parse(String)
    // ------------------------------------------------------------------------

    @Test
    void parseString_whenJwtIsInvalid_throwsWrappingParseException() {
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse("not-a-jwt")
        );
        assertEquals("Error parsing Status List Credential JWT", ex.getMessage());
        assertNotNull(ex.getCause());
    }

    @Test
    void parseString_whenJwtIsValid_parsesSuccessfully() throws Exception {
        byte[] raw = new byte[] { (byte) 0b1000_0000, (byte) 0b0000_0001 };
        String encodedList = multibaseBase64UrlGzip(raw);

        SignedJWT jwt = buildSignedJwtWithCredentialSubject(
                "https://issuer.example",
                "revocation",
                encodedList
        );

        StatusListCredentialData data = service.parse(jwt.serialize());

        assertEquals("https://issuer.example", data.issuer());
        assertEquals("revocation", data.statusPurpose());
        assertArrayEquals(raw, data.rawBitstringBytes());
    }

    // ------------------------------------------------------------------------
    // parse(SignedJWT)
    // ------------------------------------------------------------------------

    @Test
    void parseSignedJwt_whenHappyPath_extractsIssuerPurposeAndRawBytes() throws Exception {
        byte[] raw = new byte[] { (byte) 0b1000_0000, (byte) 0b0100_0000, (byte) 0b0000_0001 };
        String encodedList = multibaseBase64UrlGzip(raw);

        SignedJWT jwt = buildSignedJwtWithCredentialSubject(
                "did:example:issuer",
                "suspension",
                encodedList
        );

        StatusListCredentialData data = service.parse(jwt);

        assertEquals("did:example:issuer", data.issuer());
        assertEquals("suspension", data.statusPurpose());
        assertArrayEquals(raw, data.rawBitstringBytes());
    }

    @Test
    void parseSignedJwt_whenCredentialSubjectMissing_throws() throws Exception {
        SignedJWT jwt = buildSignedJwtWithClaims("did:example:issuer", new HashMap<>());

        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse(jwt)
        );
        assertEquals("Missing or invalid 'credentialSubject'", ex.getMessage());
    }

    @Test
    void parseSignedJwt_whenCredentialSubjectIsNotObject_throws() throws Exception {
        Map<String, Object> claims = new HashMap<>();
        claims.put("credentialSubject", "not-an-object");

        SignedJWT jwt = buildSignedJwtWithClaims("did:example:issuer", claims);

        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse(jwt)
        );
        assertEquals("Missing or invalid 'credentialSubject'", ex.getMessage());
    }

    @Test
    void parseSignedJwt_whenStatusPurposeMissing_throws() throws Exception {
        Map<String, Object> credentialSubject = new HashMap<>();
        credentialSubject.put("encodedList", multibaseBase64UrlGzip(new byte[] { 1, 2, 3 }));

        Map<String, Object> claims = new HashMap<>();
        claims.put("credentialSubject", credentialSubject);

        SignedJWT jwt = buildSignedJwtWithClaims("did:example:issuer", claims);

        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse(jwt)
        );
        assertEquals("Missing or invalid 'statusPurpose'", ex.getMessage());
    }

    @Test
    void parseSignedJwt_whenEncodedListMissing_throws() throws Exception {
        Map<String, Object> credentialSubject = new HashMap<>();
        credentialSubject.put("statusPurpose", "revocation");

        Map<String, Object> claims = new HashMap<>();
        claims.put("credentialSubject", credentialSubject);

        SignedJWT jwt = buildSignedJwtWithClaims("did:example:issuer", claims);

        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse(jwt)
        );
        assertEquals("Missing or invalid 'encodedList'", ex.getMessage());
    }

    @Test
    void parseSignedJwt_whenEncodedListDoesNotStartWithU_throws() throws Exception {
        Map<String, Object> credentialSubject = new HashMap<>();
        credentialSubject.put("statusPurpose", "revocation");
        credentialSubject.put("encodedList", "x" + Base64.getUrlEncoder().withoutPadding().encodeToString("abc".getBytes(StandardCharsets.UTF_8)));

        Map<String, Object> claims = new HashMap<>();
        claims.put("credentialSubject", credentialSubject);

        SignedJWT jwt = buildSignedJwtWithClaims("did:example:issuer", claims);

        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse(jwt)
        );
        assertEquals("encodedList must start with multibase base64url prefix 'u'", ex.getMessage());
    }

    @Test
    void parseSignedJwt_whenEncodedListIsNotBase64Url_throws() throws Exception {
        Map<String, Object> credentialSubject = new HashMap<>();
        credentialSubject.put("statusPurpose", "revocation");
        credentialSubject.put("encodedList", "u***not-base64url***");

        Map<String, Object> claims = new HashMap<>();
        claims.put("credentialSubject", credentialSubject);

        SignedJWT jwt = buildSignedJwtWithClaims("did:example:issuer", claims);

        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse(jwt)
        );
        assertEquals("encodedList is not valid base64url", ex.getMessage());
        assertNotNull(ex.getCause());
    }

    @Test
    void parseSignedJwt_whenEncodedListIsNotGzip_throws() throws Exception {
        byte[] notGzip = "plain-bytes-not-gzip".getBytes(StandardCharsets.UTF_8);
        String encodedList = "u" + Base64.getUrlEncoder().withoutPadding().encodeToString(notGzip);

        SignedJWT jwt = buildSignedJwtWithCredentialSubject(
                "did:example:issuer",
                "revocation",
                encodedList
        );

        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse(jwt)
        );
        assertEquals("Failed to gunzip content", ex.getMessage());
        assertNotNull(ex.getCause());
    }

    @Test
    void parseSignedJwt_whenClaimsPayloadIsNotJson_throwsWrappingParseException() throws Exception {
        String jwtString = jwtWithNonJsonPayload();

        SignedJWT parsed = SignedJWT.parse(jwtString);

        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse(parsed)
        );
        assertEquals("Error reading Status List Credential JWT claims", ex.getMessage());
        assertNotNull(ex.getCause());
    }

    // ------------------------------------------------------------------------
    // isBitSet / maxBits
    // ------------------------------------------------------------------------

    @Test
    void isBitSet_whenRawBytesNull_throws() {
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.isBitSet(null, 0)
        );
        assertEquals("rawBytes cannot be null", ex.getMessage());
    }

    @Test
    void isBitSet_whenBitIndexNegative_throws() {
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.isBitSet(new byte[] { 0 }, -1)
        );
        assertEquals("bitIndex must be >= 0", ex.getMessage());
    }

    @Test
    void isBitSet_whenBitIndexOutOfRange_throws() {
        byte[] raw = new byte[] { 0x00 }; // 8 bits
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.isBitSet(raw, 8)
        );
        assertEquals("bitIndex out of range. maxBits=8, bitIndex=8", ex.getMessage());
    }

    @Test
    void isBitSet_whenBitsPresent_returnsCorrectValue() {
        byte[] raw = new byte[] { (byte) 0b1000_0001 }; // bitIndex 0 and 7 are true by current implementation

        assertTrue(service.isBitSet(raw, 0));
        assertFalse(service.isBitSet(raw, 1));
        assertFalse(service.isBitSet(raw, 6));
        assertTrue(service.isBitSet(raw, 7));
    }

    @Test
    void maxBits_whenRawBytesNull_throws() {
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.maxBits(null)
        );
        assertEquals("rawBytes cannot be null", ex.getMessage());
    }

    @Test
    void maxBits_whenRawBytesPresent_returnsLengthTimes8() {
        assertEquals(0, service.maxBits(new byte[] {}));
        assertEquals(8, service.maxBits(new byte[] { 0x00 }));
        assertEquals(16, service.maxBits(new byte[] { 0x00, 0x00 }));
    }

    // ------------------------------------------------------------------------
    // Test helpers
    // ------------------------------------------------------------------------

    private static SignedJWT buildSignedJwtWithCredentialSubject(
            String issuer,
            String statusPurpose,
            String encodedList
    ) throws Exception {
        Map<String, Object> credentialSubject = new HashMap<>();
        credentialSubject.put("statusPurpose", statusPurpose);
        credentialSubject.put("encodedList", encodedList);

        Map<String, Object> claims = new HashMap<>();
        claims.put("credentialSubject", credentialSubject);

        return buildSignedJwtWithClaims(issuer, claims);
    }

    private static SignedJWT buildSignedJwtWithClaims(String issuer, Map<String, Object> extraClaims) throws Exception {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .issueTime(new Date());

        for (Map.Entry<String, Object> entry : extraClaims.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }

        JWTClaimsSet claimsSet = builder.build();

        // Signature is not validated by the service, but we produce a well-formed SignedJWT string.
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT jwt = new SignedJWT(header, claimsSet);

        // Use a deterministic, sufficiently long secret for HS256.
        byte[] secret = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        jwt.sign(new com.nimbusds.jose.crypto.MACSigner(secret));

        return jwt;
    }

    private static String multibaseBase64UrlGzip(byte[] rawBytes) {
        byte[] gzipped = gzip(rawBytes);
        String b64u = Base64.getUrlEncoder().withoutPadding().encodeToString(gzipped);
        return "u" + b64u;
    }

    private static byte[] gzip(byte[] rawBytes) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             GZIPOutputStream gzip = new GZIPOutputStream(baos)) {

            gzip.write(rawBytes);
            gzip.finish();
            return baos.toByteArray();

        } catch (IOException e) {
            throw new IllegalStateException("Unexpected gzip failure in test", e);
        }
    }

    private static String jwtWithNonJsonPayload() {
        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payloadNotJson = "this-is-not-json";

        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadNotJson.getBytes(StandardCharsets.UTF_8));

        // Signature can be anything for parsing; claims parsing will fail due to non-JSON payload.
        return header + "." + payload + ".signature";
    }
}
