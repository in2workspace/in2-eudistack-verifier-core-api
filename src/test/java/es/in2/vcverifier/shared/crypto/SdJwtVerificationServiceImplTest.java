package es.in2.vcverifier.shared.crypto;
import es.in2.vcverifier.shared.crypto.SdJwtVerificationServiceImpl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.domain.exception.JWTVerificationException;
import es.in2.vcverifier.shared.domain.model.sdjwt.Disclosure;
import es.in2.vcverifier.shared.domain.model.sdjwt.SdJwt;
import es.in2.vcverifier.shared.domain.model.sdjwt.SdJwtVerificationResult;
import es.in2.vcverifier.shared.crypto.DIDService;
import es.in2.vcverifier.verifier.domain.service.TrustFrameworkService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SdJwtVerificationServiceImplTest {

    @Mock
    private DIDService didService;
    @Mock
    private TrustFrameworkService trustFrameworkService;

    private SdJwtVerificationServiceImpl service;

    private ECKey issuerKey;
    private ECKey holderKey;

    @BeforeEach
    void setUp() throws Exception {
        service = new SdJwtVerificationServiceImpl(didService, trustFrameworkService);
        issuerKey = new ECKeyGenerator(Curve.P_256).generate();
        holderKey = new ECKeyGenerator(Curve.P_256).generate();
    }

    @Test
    @DisplayName("Valid SD-JWT with disclosures and KB-JWT verifies successfully")
    void verifyPresentation_validSdJwt_succeeds() throws Exception {
        String issuerDid = "did:key:zIssuer123";
        String expectedAud = "https://verifier.example.com";
        String expectedNonce = "test-nonce-123";

        // Create disclosure
        String disclosureEncoded = createDisclosure("salt1", "given_name", "Alice");
        String digest = computeDigest(disclosureEncoded);

        // Build issuer JWT with _sd and cnf
        Map<String, Object> cnf = Map.of("jwk", holderKey.toPublicJWK().toJSONObject());
        JWTClaimsSet issuerClaims = new JWTClaimsSet.Builder()
                .issuer(issuerDid)
                .claim("vct", "LEARCredentialEmployee")
                .claim("_sd", List.of(digest))
                .claim("_sd_alg", "SHA-256")
                .claim("cnf", cnf)
                .claim("credentialSubject", Map.of("mandate", Map.of("mandator", Map.of("organizationIdentifier", "VATES-12345"))))
                .issueTime(Date.from(Instant.now().minus(1, ChronoUnit.HOURS)))
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .build();

        String issuerJwtString = signJwt(issuerClaims, issuerKey);

        // Build KB-JWT
        String sdHashInput = issuerJwtString + "~" + disclosureEncoded + "~";
        String sdHash = computeSha256(sdHashInput);

        JWTClaimsSet kbClaims = new JWTClaimsSet.Builder()
                .audience(expectedAud)
                .claim("nonce", expectedNonce)
                .claim("sd_hash", sdHash)
                .issueTime(new Date())
                .build();
        String kbJwtString = signJwt(kbClaims, holderKey);

        String compact = issuerJwtString + "~" + disclosureEncoded + "~" + kbJwtString;

        when(didService.getPublicKeyFromDid(issuerDid)).thenReturn(issuerKey.toECPublicKey());
        when(trustFrameworkService.getTrustedIssuerListData(issuerDid)).thenReturn(List.of());

        SdJwtVerificationResult result = service.verifyPresentation(compact, expectedAud, expectedNonce);

        assertNotNull(result);
        assertEquals("LEARCredentialEmployee", result.vct());
        assertEquals("Alice", result.resolvedClaims().get("given_name"));
        assertNotNull(result.holderKey());
        assertNull(result.resolvedClaims().get("_sd"));
        assertNull(result.resolvedClaims().get("cnf"));
    }

    @Test
    @DisplayName("SD-JWT with wrong issuer signature throws")
    void verifyPresentation_wrongSignature_throws() throws Exception {
        ECKey wrongKey = new ECKeyGenerator(Curve.P_256).generate();
        String issuerDid = "did:key:zWrong";

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuerDid)
                .claim("vct", "LEARCredentialEmployee")
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .build();

        String issuerJwtString = signJwt(claims, issuerKey);
        String compact = issuerJwtString + "~";

        // Return a DIFFERENT public key than what signed the JWT
        when(didService.getPublicKeyFromDid(issuerDid)).thenReturn(wrongKey.toECPublicKey());

        assertThrows(JWTVerificationException.class,
                () -> service.verifyPresentation(compact, "https://v.example.com", "nonce"));
    }

    @Test
    @DisplayName("Expired SD-JWT throws")
    void verifyPresentation_expired_throws() throws Exception {
        String issuerDid = "did:key:zExpired";

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuerDid)
                .claim("vct", "LEARCredentialEmployee")
                .expirationTime(Date.from(Instant.now().minus(1, ChronoUnit.HOURS)))
                .build();

        String issuerJwtString = signJwt(claims, issuerKey);
        String compact = issuerJwtString + "~";

        when(didService.getPublicKeyFromDid(issuerDid)).thenReturn(issuerKey.toECPublicKey());

        assertThrows(JWTVerificationException.class,
                () -> service.verifyPresentation(compact, "https://v.example.com", "nonce"));
    }

    @Test
    @DisplayName("Disclosure digest mismatch throws")
    void verifyPresentation_disclosureDigestMismatch_throws() throws Exception {
        String issuerDid = "did:key:zDigestMismatch";
        String disclosureEncoded = createDisclosure("salt", "name", "Bob");

        // _sd contains a DIFFERENT digest
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuerDid)
                .claim("vct", "LEARCredentialEmployee")
                .claim("_sd", List.of("wrongDigest123"))
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .build();

        String issuerJwtString = signJwt(claims, issuerKey);
        String compact = issuerJwtString + "~" + disclosureEncoded + "~";

        when(didService.getPublicKeyFromDid(issuerDid)).thenReturn(issuerKey.toECPublicKey());

        assertThrows(JWTVerificationException.class,
                () -> service.verifyPresentation(compact, "https://v.example.com", "nonce"));
    }

    @Test
    @DisplayName("KB-JWT with wrong nonce throws")
    void verifyPresentation_kbJwtWrongNonce_throws() throws Exception {
        String issuerDid = "did:key:zNonceFail";
        String disclosureEncoded = createDisclosure("salt", "name", "Carol");
        String digest = computeDigest(disclosureEncoded);

        Map<String, Object> cnf = Map.of("jwk", holderKey.toPublicJWK().toJSONObject());
        JWTClaimsSet issuerClaims = new JWTClaimsSet.Builder()
                .issuer(issuerDid)
                .claim("vct", "LEARCredentialEmployee")
                .claim("_sd", List.of(digest))
                .claim("cnf", cnf)
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .build();

        String issuerJwtString = signJwt(issuerClaims, issuerKey);
        String sdHashInput = issuerJwtString + "~" + disclosureEncoded + "~";
        String sdHash = computeSha256(sdHashInput);

        JWTClaimsSet kbClaims = new JWTClaimsSet.Builder()
                .audience("https://verifier.example.com")
                .claim("nonce", "WRONG-NONCE")
                .claim("sd_hash", sdHash)
                .issueTime(new Date())
                .build();
        String kbJwtString = signJwt(kbClaims, holderKey);

        String compact = issuerJwtString + "~" + disclosureEncoded + "~" + kbJwtString;

        when(didService.getPublicKeyFromDid(issuerDid)).thenReturn(issuerKey.toECPublicKey());

        assertThrows(JWTVerificationException.class,
                () -> service.verifyPresentation(compact, "https://verifier.example.com", "correct-nonce"));
    }

    @Test
    @DisplayName("KB-JWT with wrong audience throws")
    void verifyPresentation_kbJwtWrongAudience_throws() throws Exception {
        String issuerDid = "did:key:zAudFail";
        String disclosureEncoded = createDisclosure("salt", "name", "Dan");
        String digest = computeDigest(disclosureEncoded);

        Map<String, Object> cnf = Map.of("jwk", holderKey.toPublicJWK().toJSONObject());
        JWTClaimsSet issuerClaims = new JWTClaimsSet.Builder()
                .issuer(issuerDid)
                .claim("vct", "LEARCredentialEmployee")
                .claim("_sd", List.of(digest))
                .claim("cnf", cnf)
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .build();

        String issuerJwtString = signJwt(issuerClaims, issuerKey);
        String sdHashInput = issuerJwtString + "~" + disclosureEncoded + "~";
        String sdHash = computeSha256(sdHashInput);

        JWTClaimsSet kbClaims = new JWTClaimsSet.Builder()
                .audience("https://wrong.example.com")
                .claim("nonce", "nonce1")
                .claim("sd_hash", sdHash)
                .issueTime(new Date())
                .build();
        String kbJwtString = signJwt(kbClaims, holderKey);

        String compact = issuerJwtString + "~" + disclosureEncoded + "~" + kbJwtString;

        when(didService.getPublicKeyFromDid(issuerDid)).thenReturn(issuerKey.toECPublicKey());

        assertThrows(JWTVerificationException.class,
                () -> service.verifyPresentation(compact, "https://verifier.example.com", "nonce1"));
    }

    @Test
    @DisplayName("SD-JWT without KB-JWT still works (warns about missing binding)")
    void verifyPresentation_noKbJwt_succeeds() throws Exception {
        String issuerDid = "did:key:zNoKb";

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuerDid)
                .claim("vct", "LEARCredentialEmployee")
                .claim("credentialSubject", Map.of("id", "did:key:zHolder1"))
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .build();

        String issuerJwtString = signJwt(claims, issuerKey);
        String compact = issuerJwtString + "~";

        when(didService.getPublicKeyFromDid(issuerDid)).thenReturn(issuerKey.toECPublicKey());
        when(trustFrameworkService.getTrustedIssuerListData(issuerDid)).thenReturn(List.of());

        SdJwtVerificationResult result = service.verifyPresentation(compact, "https://v.example.com", "nonce");

        assertNotNull(result);
        assertEquals("LEARCredentialEmployee", result.vct());
        assertNull(result.holderKey());
    }

    @Test
    @DisplayName("SD-JWT with no DID issuer and no x5c throws")
    void verifyPresentation_noIssuerKeySource_throws() throws Exception {
        // Issuer is an HTTPS URL, not a DID, and no x5c header
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://issuer.example.com")
                .claim("vct", "LEARCredentialEmployee")
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .build();

        String issuerJwtString = signJwt(claims, issuerKey);
        String compact = issuerJwtString + "~";

        assertThrows(JWTVerificationException.class,
                () -> service.verifyPresentation(compact, "https://v.example.com", "nonce"));
    }

    // --- Helpers ---

    private String signJwt(JWTClaimsSet claims, ECKey key) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(key.getKeyID())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    private String createDisclosure(String salt, String claimName, Object claimValue) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(List.of(salt, claimName, claimValue));
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private String computeDigest(String encoded) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(encoded.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    private String computeSha256(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(input.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }
}
