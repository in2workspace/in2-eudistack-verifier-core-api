package es.in2.vcverifier.security.filters;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.config.BackendConfig;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.model.RefreshTokenDataCache;
import es.in2.vcverifier.model.validation.ExtractedClaims;
import es.in2.vcverifier.service.ClaimsExtractor;
import es.in2.vcverifier.service.JWTService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.security.Principal;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomAuthenticationProviderTest {

    private CustomAuthenticationProvider provider;

    @Mock
    private JWTService jwtService;

    @Mock
    private BackendConfig backendConfig;

    @Mock
    private CacheStore<RefreshTokenDataCache> cacheStoreForRefreshTokenData;

    @Mock
    private ClaimsExtractor claimsExtractor;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private RegisteredClientRepository registeredClientRepository;
    private OAuth2AuthorizationService oAuth2AuthorizationService;

    @BeforeEach
    void setUp() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("test-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://example.com/callback")
                .scope("openid")
                .clientSettings(ClientSettings.builder().requireProofKey(false).build())
                .build();

        registeredClientRepository = new InMemoryRegisteredClientRepository(registeredClient);
        oAuth2AuthorizationService = new InMemoryOAuth2AuthorizationService();

        provider = new CustomAuthenticationProvider(
                jwtService,
                registeredClientRepository,
                backendConfig,
                objectMapper,
                cacheStoreForRefreshTokenData,
                oAuth2AuthorizationService,
                List.of(claimsExtractor)
        );
    }

    @Test
    void authenticate_validAuthorizationCodeGrant_withEmployeeCredential_success() {
        JsonNode vcJson = buildEmployeeCredentialV1();
        ExtractedClaims claims = buildEmployeeClaims();

        when(claimsExtractor.supports("LEARCredentialEmployee")).thenReturn(true);
        when(claimsExtractor.extract(any(JsonNode.class))).thenReturn(claims);
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
        when(jwtService.generateJWT(anyString())).thenReturn("signed-jwt-token");

        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(OAuth2ParameterNames.CLIENT_ID, "test-client");
        additionalParams.put("vc", objectMapper.convertValue(vcJson, Map.class));
        additionalParams.put(OAuth2ParameterNames.AUDIENCE, "https://rp.example.com");
        additionalParams.put(OAuth2ParameterNames.SCOPE, "openid");

        storeAuthorizationCode("test-code");

        OAuth2AuthorizationCodeAuthenticationToken authToken = new OAuth2AuthorizationCodeAuthenticationToken(
                "test-code",
                mock(Authentication.class),
                "https://example.com/callback",
                additionalParams
        );

        Authentication result = provider.authenticate(authToken);

        assertNotNull(result);
        assertInstanceOf(OAuth2AccessTokenAuthenticationToken.class, result);
        // access token + id token
        verify(jwtService, times(2)).generateJWT(anyString());
    }

    @Test
    void authenticate_validClientCredentialsGrant_withMachineCredential_success() {
        JsonNode vcJson = buildMachineCredentialV1();
        ExtractedClaims claims = buildMachineClaims();

        when(claimsExtractor.supports("LEARCredentialMachine")).thenReturn(true);
        when(claimsExtractor.extract(any(JsonNode.class))).thenReturn(claims);
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
        when(jwtService.generateJWT(anyString())).thenReturn("signed-jwt-token");

        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(OAuth2ParameterNames.CLIENT_ID, "test-client");
        additionalParams.put("vc", objectMapper.convertValue(vcJson, Map.class));

        OAuth2ClientCredentialsAuthenticationToken authToken = new OAuth2ClientCredentialsAuthenticationToken(
                mock(Authentication.class),
                null,
                additionalParams
        );

        Authentication result = provider.authenticate(authToken);

        assertNotNull(result);
        assertInstanceOf(OAuth2AccessTokenAuthenticationToken.class, result);
        // access token only (no id token for client_credentials)
        verify(jwtService, times(1)).generateJWT(anyString());
    }

    @Test
    void authenticate_missingVcParameter_throwsException() {
        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(OAuth2ParameterNames.CLIENT_ID, "test-client");

        OAuth2ClientCredentialsAuthenticationToken authToken = new OAuth2ClientCredentialsAuthenticationToken(
                mock(Authentication.class),
                null,
                additionalParams
        );

        assertThrows(OAuth2AuthenticationException.class, () -> provider.authenticate(authToken));
    }

    @Test
    void authenticate_missingAudienceForEmployee_throwsException() {
        JsonNode vcJson = buildEmployeeCredentialV1();
        ExtractedClaims claims = buildEmployeeClaims();

        when(claimsExtractor.supports("LEARCredentialEmployee")).thenReturn(true);
        when(claimsExtractor.extract(any(JsonNode.class))).thenReturn(claims);

        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(OAuth2ParameterNames.CLIENT_ID, "test-client");
        additionalParams.put("vc", objectMapper.convertValue(vcJson, Map.class));
        // No AUDIENCE parameter

        storeAuthorizationCode("test-code-no-aud");

        OAuth2AuthorizationCodeAuthenticationToken authToken = new OAuth2AuthorizationCodeAuthenticationToken(
                "test-code-no-aud",
                mock(Authentication.class),
                "https://example.com/callback",
                additionalParams
        );

        assertThrows(OAuth2AuthenticationException.class, () -> provider.authenticate(authToken));
    }

    @Test
    void authenticate_noClaimsExtractorForType_throwsException() {
        JsonNode vcJson = buildCredentialJsonNode("UnknownCredentialType");

        when(claimsExtractor.supports("UnknownCredentialType")).thenReturn(false);

        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(OAuth2ParameterNames.CLIENT_ID, "test-client");
        additionalParams.put("vc", objectMapper.convertValue(vcJson, Map.class));

        OAuth2ClientCredentialsAuthenticationToken authToken = new OAuth2ClientCredentialsAuthenticationToken(
                mock(Authentication.class),
                null,
                additionalParams
        );

        assertThrows(OAuth2AuthenticationException.class, () -> provider.authenticate(authToken));
    }

    @Test
    void authenticate_unsupportedGrantType_throwsException() {
        Authentication unsupported = mock(Authentication.class);
        assertThrows(OAuth2AuthenticationException.class, () -> provider.authenticate(unsupported));
    }

    @Test
    void authenticate_machineCredential_audience_isBackendUrl() {
        JsonNode vcJson = buildMachineCredentialV1();
        ExtractedClaims claims = buildMachineClaims();

        when(claimsExtractor.supports("LEARCredentialMachine")).thenReturn(true);
        when(claimsExtractor.extract(any(JsonNode.class))).thenReturn(claims);
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
        when(jwtService.generateJWT(anyString())).thenAnswer(invocation -> {
            String claimsStr = invocation.getArgument(0);
            // Verify audience is the backend URL for machine credentials
            assertTrue(claimsStr.contains("verifier.example.com"));
            return "signed-jwt-token";
        });

        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(OAuth2ParameterNames.CLIENT_ID, "test-client");
        additionalParams.put("vc", objectMapper.convertValue(vcJson, Map.class));

        OAuth2ClientCredentialsAuthenticationToken authToken = new OAuth2ClientCredentialsAuthenticationToken(
                mock(Authentication.class),
                null,
                additionalParams
        );

        Authentication result = provider.authenticate(authToken);
        assertNotNull(result);
    }

    @Test
    void supports_correctAuthenticationTypes() {
        assertTrue(provider.supports(OAuth2AuthorizationCodeAuthenticationToken.class));
        assertTrue(provider.supports(OAuth2ClientCredentialsAuthenticationToken.class));
        assertTrue(provider.supports(OAuth2RefreshTokenAuthenticationToken.class));
        assertFalse(provider.supports(Authentication.class));
    }

    @Test
    void authenticate_subjectDid_resolvedFromExtractedClaims() {
        JsonNode vcJson = buildEmployeeCredentialV1();
        ExtractedClaims claims = ExtractedClaims.builder()
                .subjectDid("did:key:zFromExtractor")
                .mandatorOrgId("VATES-12345678")
                .issuerDid("did:elsi:VATES-12345678")
                .idTokenClaims(Map.of())
                .accessTokenClaims(Map.of())
                .scope("openid learcredential")
                .build();

        when(claimsExtractor.supports("LEARCredentialEmployee")).thenReturn(true);
        when(claimsExtractor.extract(any(JsonNode.class))).thenReturn(claims);
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
        when(jwtService.generateJWT(anyString())).thenAnswer(invocation -> {
            String claimsStr = invocation.getArgument(0);
            assertTrue(claimsStr.contains("did:key:zFromExtractor"));
            return "signed-jwt-token";
        });

        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(OAuth2ParameterNames.CLIENT_ID, "test-client");
        additionalParams.put("vc", objectMapper.convertValue(vcJson, Map.class));
        additionalParams.put(OAuth2ParameterNames.AUDIENCE, "https://rp.example.com");

        storeAuthorizationCode("test-code-sub");

        OAuth2AuthorizationCodeAuthenticationToken authToken = new OAuth2AuthorizationCodeAuthenticationToken(
                "test-code-sub",
                mock(Authentication.class),
                "https://example.com/callback",
                additionalParams
        );

        Authentication result = provider.authenticate(authToken);
        assertNotNull(result);
    }

    // --- Helper methods ---

    private void storeAuthorizationCode(String code) {
        RegisteredClient rc = registeredClientRepository.findByClientId("test-client");
        OAuth2Authorization auth = OAuth2Authorization.withRegisteredClient(rc)
                .id(UUID.randomUUID().toString())
                .principalName("test-client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .token(new org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode(
                        code, Instant.now(), Instant.now().plusSeconds(300)))
                .attribute(OAuth2ParameterNames.CLIENT_ID, "test-client")
                .attribute(Principal.class.getName(), mock(Authentication.class))
                .build();
        oAuth2AuthorizationService.save(auth);
    }

    private JsonNode buildEmployeeCredentialV1() {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode context = vc.putArray("@context");
        context.add("https://www.w3.org/ns/credentials/v2");
        context.add("https://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1");

        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("LEARCredentialEmployee");

        vc.putObject("issuer").put("id", "did:elsi:VATES-12345678");
        vc.put("validFrom", "2024-01-01T00:00:00Z");
        vc.put("validUntil", "2025-01-01T00:00:00Z");

        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", "did:key:zDnaeTest123");
        ObjectNode mandate = cs.putObject("mandate");
        ObjectNode mandatee = mandate.putObject("mandatee");
        mandatee.put("id", "did:key:zDnaeTest123");
        mandatee.put("first_name", "John");
        mandatee.put("last_name", "Doe");
        mandatee.put("email", "john@example.com");
        ObjectNode mandator = mandate.putObject("mandator");
        mandator.put("organizationIdentifier", "VATES-12345678");
        mandate.putArray("power");

        return vc;
    }

    private JsonNode buildMachineCredentialV1() {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode context = vc.putArray("@context");
        context.add("https://www.w3.org/ns/credentials/v2");

        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("LEARCredentialMachine");

        vc.putObject("issuer").put("id", "did:elsi:VATES-12345678");

        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", "did:key:zDnaeMachine123");
        ObjectNode mandate = cs.putObject("mandate");
        mandate.putObject("mandatee").put("id", "did:key:zDnaeMachine123");
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");
        mandate.putArray("power");

        return vc;
    }

    private JsonNode buildCredentialJsonNode(String credentialType) {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        vc.putArray("@context").add("https://www.w3.org/ns/credentials/v2");

        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add(credentialType);

        vc.putObject("issuer").put("id", "did:elsi:VATES-12345678");

        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", "did:key:zDnaeTest123");
        ObjectNode mandate = cs.putObject("mandate");
        mandate.putObject("mandatee").put("id", "did:key:zDnaeTest123");
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");
        mandate.putArray("power");

        return vc;
    }

    private ExtractedClaims buildEmployeeClaims() {
        return ExtractedClaims.builder()
                .subjectDid("did:key:zDnaeTest123")
                .mandatorOrgId("VATES-12345678")
                .issuerDid("did:elsi:VATES-12345678")
                .idTokenClaims(Map.of(
                        "name", "John Doe",
                        "given_name", "John",
                        "family_name", "Doe",
                        "email", "john@example.com",
                        "email_verified", true
                ))
                .accessTokenClaims(Map.of())
                .scope("openid learcredential")
                .build();
    }

    private ExtractedClaims buildMachineClaims() {
        return ExtractedClaims.builder()
                .subjectDid("did:key:zDnaeMachine123")
                .mandatorOrgId("VATES-12345678")
                .issuerDid("did:elsi:VATES-12345678")
                .idTokenClaims(Map.of())
                .accessTokenClaims(Map.of())
                .scope("machine learcredential")
                .build();
    }
}
