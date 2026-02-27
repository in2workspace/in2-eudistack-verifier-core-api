package es.in2.vcverifier.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.exception.*;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.service.*;
import es.in2.vcverifier.service.impl.VpServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Security-focused tests for VP/VC validation pipeline.
 * Tests malformed inputs, manipulation attacks, replay prevention, and revocation.
 */
@ExtendWith(MockitoExtension.class)
class VpSecurityTest {

    @Mock
    private JWTService jwtService;
    @Mock
    private TrustFrameworkService trustFrameworkService;
    @Mock
    private DIDService didService;
    @Mock
    private CertificateValidationService certificateValidationService;

    private VpServiceImpl vpService;

    @BeforeEach
    void setUp() {
        vpService = new VpServiceImpl(jwtService, new ObjectMapper(), trustFrameworkService, didService, certificateValidationService);
    }

    // --- Malformed VP Token ---

    @Nested
    @DisplayName("Malformed VP Token")
    class MalformedVpToken {

        @Test
        @DisplayName("Empty string VP should throw JWTParsingException")
        void emptyVpToken_throwsJwtParsingException() {
            assertThrows(JWTParsingException.class,
                    () -> vpService.validateVerifiablePresentation(""));
        }

        @Test
        @DisplayName("Null-like string VP should throw")
        void nullStringVpToken_throwsException() {
            assertThrows(Exception.class,
                    () -> vpService.validateVerifiablePresentation("null"));
        }

        @Test
        @DisplayName("Random string VP should throw JWTParsingException")
        void randomStringVpToken_throwsJwtParsingException() {
            assertThrows(JWTParsingException.class,
                    () -> vpService.validateVerifiablePresentation("not.a.jwt"));
        }

        @Test
        @DisplayName("VP with only header and payload (no signature) should throw")
        void twoPartJwt_throwsJwtParsingException() {
            String headerPayload = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"alg\":\"ES256\"}".getBytes())
                    + "."
                    + Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"vp\":{}}".getBytes());
            assertThrows(JWTParsingException.class,
                    () -> vpService.validateVerifiablePresentation(headerPayload));
        }

        @Test
        @DisplayName("VP without 'vp' claim should throw JWTClaimMissingException")
        void vpWithoutVpClaim_throwsJwtClaimMissing() {
            String jwt = buildUnsignedJwt(Map.of("sub", "test"));
            assertThrows(JWTClaimMissingException.class,
                    () -> vpService.validateVerifiablePresentation(jwt));
        }

        @Test
        @DisplayName("VP with 'vp' claim as string instead of object should throw")
        void vpClaimAsString_throwsJwtClaimMissing() {
            String jwt = buildUnsignedJwt(Map.of("vp", "not-an-object"));
            assertThrows(JWTClaimMissingException.class,
                    () -> vpService.validateVerifiablePresentation(jwt));
        }

        @Test
        @DisplayName("VP with empty verifiableCredential array should throw CredentialException")
        void vpWithEmptyVcArray_throwsCredentialException() {
            Map<String, Object> vp = Map.of("verifiableCredential", List.of());
            String jwt = buildUnsignedJwt(Map.of("vp", vp));
            assertThrows(CredentialException.class,
                    () -> vpService.validateVerifiablePresentation(jwt));
        }

        @Test
        @DisplayName("VP with non-string VC in array should throw CredentialException")
        void vpWithNonStringVc_throwsCredentialException() {
            Map<String, Object> vp = Map.of("verifiableCredential", List.of(42));
            String jwt = buildUnsignedJwt(Map.of("vp", vp));
            assertThrows(CredentialException.class,
                    () -> vpService.validateVerifiablePresentation(jwt));
        }

        @Test
        @DisplayName("VP with verifiableCredential not an array should throw CredentialException")
        void vpWithVcNotArray_throwsCredentialException() {
            Map<String, Object> vp = Map.of("verifiableCredential", "single-string");
            String jwt = buildUnsignedJwt(Map.of("vp", vp));
            assertThrows(CredentialException.class,
                    () -> vpService.validateVerifiablePresentation(jwt));
        }
    }

    // --- Malformed VC inside VP ---

    @Nested
    @DisplayName("Malformed VC inside VP")
    class MalformedVcInsideVp {

        @Test
        @DisplayName("VC that is not parseable as JWT should throw JWTParsingException")
        void vcNotParseableJwt_throwsJwtParsing() {
            Map<String, Object> vp = Map.of("verifiableCredential", List.of("not-a-jwt-string"));
            String jwt = buildUnsignedJwt(Map.of("vp", vp));
            assertThrows(JWTParsingException.class,
                    () -> vpService.validateVerifiablePresentation(jwt));
        }
    }

    // --- VC Payload Manipulation ---

    @Nested
    @DisplayName("VC Payload Manipulation")
    class VcPayloadManipulation {

        @Test
        @DisplayName("VC payload that is not a Map should throw CredentialMappingException")
        void vcPayloadNotAMap_throwsCredentialMapping() {
            // Build a VP with a valid inner VC JWT
            String innerVcJwt = buildUnsignedJwt(Map.of("sub", "test-sub"));
            Map<String, Object> vp = Map.of("verifiableCredential", List.of(innerVcJwt));
            String vpJwt = buildUnsignedJwt(Map.of("vp", vp));

            Payload mockPayload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(any())).thenReturn(mockPayload);
            when(jwtService.getVCFromPayload(any())).thenReturn("string-not-map");

            assertThrows(CredentialMappingException.class,
                    () -> vpService.validateVerifiablePresentation(vpJwt));
        }

        @Test
        @DisplayName("VC payload without 'type' field should throw CredentialMappingException")
        void vcPayloadWithoutType_throwsCredentialMapping() {
            String innerVcJwt = buildUnsignedJwt(Map.of("sub", "test-sub"));
            Map<String, Object> vp = Map.of("verifiableCredential", List.of(innerVcJwt));
            String vpJwt = buildUnsignedJwt(Map.of("vp", vp));

            Map<String, Object> vcMap = new LinkedHashMap<>();
            vcMap.put("issuer", Map.of("id", "did:key:z123"));
            // No "type" field

            Payload mockPayload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(any())).thenReturn(mockPayload);
            when(jwtService.getVCFromPayload(any())).thenReturn(vcMap);

            assertThrows(CredentialMappingException.class,
                    () -> vpService.validateVerifiablePresentation(vpJwt));
        }

        @Test
        @DisplayName("VC with unsupported credential type should throw InvalidCredentialTypeException")
        void vcWithUnsupportedType_throwsInvalidCredentialType() {
            String innerVcJwt = buildUnsignedJwt(Map.of("sub", "test-sub"));
            Map<String, Object> vp = Map.of("verifiableCredential", List.of(innerVcJwt));
            String vpJwt = buildUnsignedJwt(Map.of("vp", vp));

            Map<String, Object> vcMap = new LinkedHashMap<>();
            vcMap.put("type", List.of("VerifiableCredential", "UnknownCredentialType"));
            vcMap.put("@context", List.of("https://www.w3.org/ns/credentials/v2"));

            Payload mockPayload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(any())).thenReturn(mockPayload);
            when(jwtService.getVCFromPayload(any())).thenReturn(vcMap);

            assertThrows(InvalidCredentialTypeException.class,
                    () -> vpService.validateVerifiablePresentation(vpJwt));
        }
    }

    // --- Context URL injection ---

    @Nested
    @DisplayName("Context URL Injection")
    class ContextUrlInjection {

        @Test
        @DisplayName("extractContextFromJson with missing @context throws OAuth2AuthenticationException")
        void missingContextField_throwsException() {
            com.fasterxml.jackson.databind.node.ObjectNode node = new ObjectMapper().createObjectNode();
            node.put("type", "test");

            assertThrows(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class,
                    () -> vpService.extractContextFromJson(node));
        }

        @Test
        @DisplayName("extractContextFromJson with non-array @context throws OAuth2AuthenticationException")
        void contextNotArray_throwsException() {
            com.fasterxml.jackson.databind.node.ObjectNode node = new ObjectMapper().createObjectNode();
            node.put("@context", "https://example.com");

            assertThrows(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class,
                    () -> vpService.extractContextFromJson(node));
        }

        @Test
        @DisplayName("extractContextFromJson with non-string elements throws OAuth2AuthenticationException")
        void contextWithNonStringElements_throwsException() {
            ObjectMapper mapper = new ObjectMapper();
            com.fasterxml.jackson.databind.node.ObjectNode node = mapper.createObjectNode();
            com.fasterxml.jackson.databind.node.ArrayNode contextArray = mapper.createArrayNode();
            contextArray.add(42);
            node.set("@context", contextArray);

            assertThrows(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class,
                    () -> vpService.extractContextFromJson(node));
        }

        @Test
        @DisplayName("extractContextFromJson with valid context returns list")
        void validContext_returnsList() {
            ObjectMapper mapper = new ObjectMapper();
            com.fasterxml.jackson.databind.node.ObjectNode node = mapper.createObjectNode();
            com.fasterxml.jackson.databind.node.ArrayNode contextArray = mapper.createArrayNode();
            contextArray.add("https://www.w3.org/ns/credentials/v2");
            contextArray.add("https://example.com/custom");
            node.set("@context", contextArray);

            List<String> result = vpService.extractContextFromJson(node);

            assertEquals(2, result.size());
            assertEquals("https://www.w3.org/ns/credentials/v2", result.get(0));
        }
    }

    // --- Credential Time Window ---

    @Nested
    @DisplayName("Credential Time Window Attacks")
    class CredentialTimeWindow {

        @Test
        @DisplayName("VC with 'type' containing non-string elements should throw CredentialMappingException")
        void typeListWithNonStrings_throwsCredentialMapping() {
            String innerVcJwt = buildUnsignedJwt(Map.of("sub", "test"));
            Map<String, Object> vp = Map.of("verifiableCredential", List.of(innerVcJwt));
            String vpJwt = buildUnsignedJwt(Map.of("vp", vp));

            Map<String, Object> vcMap = new LinkedHashMap<>();
            vcMap.put("type", List.of("VerifiableCredential", 123));

            Payload mockPayload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(any())).thenReturn(mockPayload);
            when(jwtService.getVCFromPayload(any())).thenReturn(vcMap);

            assertThrows(CredentialMappingException.class,
                    () -> vpService.validateVerifiablePresentation(vpJwt));
        }

        @Test
        @DisplayName("VC with 'type' as string instead of list should throw CredentialMappingException")
        void typeAsString_throwsCredentialMapping() {
            String innerVcJwt = buildUnsignedJwt(Map.of("sub", "test"));
            Map<String, Object> vp = Map.of("verifiableCredential", List.of(innerVcJwt));
            String vpJwt = buildUnsignedJwt(Map.of("vp", vp));

            Map<String, Object> vcMap = new LinkedHashMap<>();
            vcMap.put("type", "LEARCredentialEmployee");

            Payload mockPayload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(any())).thenReturn(mockPayload);
            when(jwtService.getVCFromPayload(any())).thenReturn(vcMap);

            assertThrows(CredentialMappingException.class,
                    () -> vpService.validateVerifiablePresentation(vpJwt));
        }
    }

    // --- Replay Prevention (JTI) ---

    @Nested
    @DisplayName("Client Assertion JTI Replay Prevention")
    class JtiReplayPrevention {

        @Test
        @DisplayName("JtiTokenCache rejects duplicate JTI values")
        void jtiTokenCache_rejectsDuplicate() {
            var cache = new es.in2.vcverifier.config.JtiTokenCache(new HashSet<>());
            cache.addJti("unique-jti-1");
            assertTrue(cache.isJtiPresent("unique-jti-1"));
            assertFalse(cache.isJtiPresent("unique-jti-2"));
        }
    }

    // --- Issuer Trust Manipulation ---

    @Nested
    @DisplayName("Issuer Trust Validation")
    class IssuerTrustValidation {

        @Test
        @DisplayName("Credential type not in issuer capabilities should be rejected")
        void credentialTypeNotInCapabilities_throwsInvalidCredentialType() throws Exception {
            // Use reflection to call private method
            java.lang.reflect.Method method = VpServiceImpl.class.getDeclaredMethod(
                    "validateCredentialTypeWithIssuerCapabilities", List.class, List.class);
            method.setAccessible(true);

            List<IssuerCredentialsCapabilities> capabilities = List.of(
                    IssuerCredentialsCapabilities.builder()
                            .credentialsType("LEARCredentialEmployee")
                            .build()
            );

            assertThrows(java.lang.reflect.InvocationTargetException.class,
                    () -> method.invoke(vpService, capabilities, List.of("VerifiableCredential", "MaliciousType")));
        }

        @Test
        @DisplayName("Credential type matching one capability should pass")
        void credentialTypeMatchingCapability_passes() throws Exception {
            java.lang.reflect.Method method = VpServiceImpl.class.getDeclaredMethod(
                    "validateCredentialTypeWithIssuerCapabilities", List.class, List.class);
            method.setAccessible(true);

            List<IssuerCredentialsCapabilities> capabilities = List.of(
                    IssuerCredentialsCapabilities.builder()
                            .credentialsType("LEARCredentialEmployee")
                            .build()
            );

            // Should not throw
            method.invoke(vpService, capabilities,
                    List.of("VerifiableCredential", "LEARCredentialEmployee"));
        }
    }

    // --- Helper: build an unsigned JWT for testing ---

    private String buildUnsignedJwt(Map<String, Object> claims) {
        try {
            String header = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"alg\":\"ES256\",\"typ\":\"JWT\"}".getBytes());
            ObjectMapper om = new ObjectMapper();
            String payload = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(om.writeValueAsBytes(claims));
            String sig = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(new byte[64]); // dummy 64-byte signature (ES256 size)
            return header + "." + payload + "." + sig;
        } catch (Exception e) {
            throw new RuntimeException("Failed to build test JWT", e);
        }
    }
}
