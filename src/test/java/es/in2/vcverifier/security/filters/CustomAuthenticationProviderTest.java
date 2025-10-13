package es.in2.vcverifier.security.filters;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import es.in2.vcverifier.config.BackendConfig;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.model.RefreshTokenDataCache;
import es.in2.vcverifier.model.credentials.DetailedIssuer;
import es.in2.vcverifier.model.credentials.SimpleIssuer;
import es.in2.vcverifier.model.credentials.lear.LEARCredential;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV1;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV2;
import es.in2.vcverifier.model.credentials.lear.employee.subject.CredentialSubjectV2;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.MandateV1;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.MandateV2;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.mandatee.MandateeV1;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.mandatee.MandateeV2;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.power.PowerV2;
import com.fasterxml.jackson.core.type.TypeReference;
import es.in2.vcverifier.model.credentials.lear.machine.LEARCredentialMachineV1;
import es.in2.vcverifier.model.credentials.lear.machine.LEARCredentialMachineV2;
import static es.in2.vcverifier.util.Constants.LEAR_CREDENTIAL_MACHINE_V2_CONTEXT;
import es.in2.vcverifier.service.JWTService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

import static es.in2.vcverifier.util.Constants.LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT;
import static es.in2.vcverifier.util.Constants.LEAR_CREDENTIAL_EMPLOYEE_V2_CONTEXT;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomAuthenticationProviderTest {

    @Mock
    private JWTService jwtService;

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @Mock
    private BackendConfig backendConfig;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private CacheStore<RefreshTokenDataCache> cacheStoreForRefreshTokenData;
    @Mock
    private OAuth2AuthorizationService oAuth2AuthorizationService;

    @InjectMocks
    private CustomAuthenticationProvider customAuthenticationProvider;

    @Test
    void authenticate_validAuthorizationCodeGrant_withEmployeeCredentialV1_success() throws Exception {
        // Arrange
        String clientId = "test-client-id";
        String audience = "test-audience";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("client_id", clientId);
        additionalParameters.put(OAuth2ParameterNames.AUDIENCE, audience);
        additionalParameters.put(OAuth2ParameterNames.SCOPE, "openid profile email");

        Map<String, Object> vcMap = new HashMap<>();
        vcMap.put("type", List.of("VerifiableCredential", "LEARCredentialEmployee"));
        additionalParameters.put("vc", vcMap);

        OAuth2AuthorizationCodeAuthenticationToken authToken = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(authToken.getAdditionalParameters()).thenReturn(additionalParameters);

        TestingAuthenticationToken principal = new TestingAuthenticationToken("user", null);
        when(authToken.getPrincipal()).thenReturn(principal);

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
        when(registeredClient.getClientId()).thenReturn("test-client-id");

        when(backendConfig.getUrl()).thenReturn("https://auth.server");

        JsonNode vcJsonNode = mock(JsonNode.class);
        when(objectMapper.convertValue(vcMap, JsonNode.class)).thenReturn(vcJsonNode);
        ArrayNode contextNode = JsonNodeFactory.instance.arrayNode();
        for (String ctx : LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT) {
            contextNode.add(ctx);
        }
        when(vcJsonNode.get("@context")).thenReturn(contextNode);

        LEARCredentialEmployeeV1 learCredentialEmployeeV1 = getLEARCredentialEmployeeV1();
        when(objectMapper.convertValue(vcJsonNode, LEARCredentialEmployeeV1.class)).thenReturn(learCredentialEmployeeV1);

        when(objectMapper.writeValueAsString(learCredentialEmployeeV1)).thenReturn("{\"credential\":\"value\"}");

        when(jwtService.generateJWT(anyString())).thenReturn("mock-jwt-token");

        // Act
        Authentication result = customAuthenticationProvider.authenticate(authToken);

        // Assert
        assertNotNull(result);
        assertInstanceOf(OAuth2AccessTokenAuthenticationToken.class, result);

        OAuth2AccessTokenAuthenticationToken tokenResult = (OAuth2AccessTokenAuthenticationToken) result;
        assertEquals("mock-jwt-token", tokenResult.getAccessToken().getTokenValue());

        Map<String, Object> additionalParams = tokenResult.getAdditionalParameters();
        assertTrue(additionalParams.containsKey("id_token"));
        assertEquals("mock-jwt-token", additionalParams.get("id_token"));

        verify(jwtService, times(2)).generateJWT(anyString());

        // Verify refresh token data cache
        ArgumentCaptor<String> refreshTokenCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<RefreshTokenDataCache> refreshTokenDataCaptor = ArgumentCaptor.forClass(RefreshTokenDataCache.class);
        verify(cacheStoreForRefreshTokenData).add(refreshTokenCaptor.capture(), refreshTokenDataCaptor.capture());

        // Verify OAuth2AuthorizationService saved
        ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(oAuth2AuthorizationService).save(authorizationCaptor.capture());
    }

    @Test
    void extractContextFromJson_missingContext_throwsException() {
        // Arrange
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("client_id", clientId);

        Map<String, Object> vcMap = new HashMap<>();
        vcMap.put("type", List.of("VerifiableCredential", "LEARCredentialEmployee"));
        additionalParameters.put("vc", vcMap);

        OAuth2AuthorizationCodeAuthenticationToken authToken = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(authToken.getAdditionalParameters()).thenReturn(additionalParameters);

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        JsonNode vcJsonNode = mock(JsonNode.class);
        when(objectMapper.convertValue(vcMap, JsonNode.class)).thenReturn(vcJsonNode);
        when(vcJsonNode.get("@context")).thenReturn(null);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(authToken));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
    }

    @Test
    void extractContextFromJson_contextNotArray_throwsException() {
        // Arrange
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("client_id", clientId);

        Map<String, Object> vcMap = new HashMap<>();
        vcMap.put("type", List.of("VerifiableCredential", "LEARCredentialEmployee"));
        additionalParameters.put("vc", vcMap);

        OAuth2AuthorizationCodeAuthenticationToken authToken = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(authToken.getAdditionalParameters()).thenReturn(additionalParameters);

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        JsonNode vcJsonNode = mock(JsonNode.class);
        when(objectMapper.convertValue(vcMap, JsonNode.class)).thenReturn(vcJsonNode);
        when(vcJsonNode.get("@context")).thenReturn(JsonNodeFactory.instance.textNode("not an array"));

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(authToken));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
    }

    @Test
    void getVerifiableCredential_unknownEmployeeVersion_throwsException() {
        // Arrange
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("client_id", clientId);

        Map<String, Object> vcMap = new HashMap<>();
        vcMap.put("type", List.of("VerifiableCredential", "LEARCredentialEmployee"));
        additionalParameters.put("vc", vcMap);

        OAuth2AuthorizationCodeAuthenticationToken authToken = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(authToken.getAdditionalParameters()).thenReturn(additionalParameters);

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        JsonNode vcJsonNode = mock(JsonNode.class);
        when(objectMapper.convertValue(vcMap, JsonNode.class)).thenReturn(vcJsonNode);
        ArrayNode contextNode = JsonNodeFactory.instance.arrayNode();
        contextNode.add("https://unknown-context");
        when(vcJsonNode.get("@context")).thenReturn(contextNode);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(authToken));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
    }

    @Test
    void authenticate_validAuthorizationCodeGrant_withEmployeeCredentialV2_success() throws Exception {
        // Arrange
        String clientId = "test-client-id";
        String audience = "test-audience";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("client_id", clientId);
        additionalParameters.put(OAuth2ParameterNames.AUDIENCE, audience);
        additionalParameters.put(OAuth2ParameterNames.SCOPE, "openid profile email");

        Map<String, Object> vcMap = new HashMap<>();
        vcMap.put("type", List.of("VerifiableCredential", "LEARCredentialEmployee"));
        additionalParameters.put("vc", vcMap);

        OAuth2AuthorizationCodeAuthenticationToken authToken = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(authToken.getAdditionalParameters()).thenReturn(additionalParameters);

        TestingAuthenticationToken principal = new TestingAuthenticationToken("user", null);
        when(authToken.getPrincipal()).thenReturn(principal);

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
        when(registeredClient.getClientId()).thenReturn("test-client-id");

        when(backendConfig.getUrl()).thenReturn("https://auth.server");

        JsonNode vcJsonNode = mock(JsonNode.class);
        when(objectMapper.convertValue(vcMap, JsonNode.class)).thenReturn(vcJsonNode);
        ArrayNode contextNode = JsonNodeFactory.instance.arrayNode();
        for (String ctx : LEAR_CREDENTIAL_EMPLOYEE_V2_CONTEXT) {
            contextNode.add(ctx);
        }
        when(vcJsonNode.get("@context")).thenReturn(contextNode);

        LEARCredentialEmployeeV2 normalizedLearCredentialEmployeeV2 = getLEARCredentialEmployeeV2();
        when(objectMapper.convertValue(vcJsonNode, LEARCredentialEmployeeV2.class)).thenReturn(normalizedLearCredentialEmployeeV2);

        when(objectMapper.writeValueAsString(normalizedLearCredentialEmployeeV2)).thenReturn("{\"credential\":\"value\"}");

        when(jwtService.generateJWT(anyString())).thenReturn("mock-jwt-token");

        // Act
        Authentication result = customAuthenticationProvider.authenticate(authToken);

        // Assert
        assertNotNull(result);
        assertInstanceOf(OAuth2AccessTokenAuthenticationToken.class, result);

        OAuth2AccessTokenAuthenticationToken tokenResult = (OAuth2AccessTokenAuthenticationToken) result;
        assertEquals("mock-jwt-token", tokenResult.getAccessToken().getTokenValue());

        Map<String, Object> additionalParams = tokenResult.getAdditionalParameters();
        assertTrue(additionalParams.containsKey("id_token"));
        assertEquals("mock-jwt-token", additionalParams.get("id_token"));

        verify(jwtService, times(2)).generateJWT(anyString());

        // Verify refresh token data cache
        ArgumentCaptor<String> refreshTokenCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<RefreshTokenDataCache> refreshTokenDataCaptor = ArgumentCaptor.forClass(RefreshTokenDataCache.class);
        verify(cacheStoreForRefreshTokenData).add(refreshTokenCaptor.capture(), refreshTokenDataCaptor.capture());

        // Verify OAuth2AuthorizationService saved
        ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(oAuth2AuthorizationService).save(authorizationCaptor.capture());
    }

//    todo @Test
//    void authenticate_validClientCredentialsGrant_withMachineCredential_success() {
//        // Arrange
//        String clientId = "test-client-id";
//        Map<String, Object> additionalParameters = new HashMap<>();
//        additionalParameters.put("client_id", clientId);
//
//        Map<String, Object> vcMap = new HashMap<>();
//        vcMap.put("type", List.of("VerifiableCredential", "LEARCredentialMachine"));
//
//        additionalParameters.put("vc", vcMap);
//        additionalParameters.put(OAuth2ParameterNames.SCOPE, "machine");
//
//        OAuth2ClientCredentialsAuthenticationToken authenticationToken = mock(OAuth2ClientCredentialsAuthenticationToken.class);
//        when(authenticationToken.getAdditionalParameters()).thenReturn(additionalParameters);
//
//        RegisteredClient registeredClient = mock(RegisteredClient.class);
//        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
//
//        when(backendConfig.getUrl()).thenReturn("https://auth.server");
//
//        JsonNode vcJsonNode = mock(JsonNode.class);
//        when(objectMapper.convertValue(vcMap, JsonNode.class)).thenReturn(vcJsonNode);
//
//        LEARCredentialMachineV1 credential = getLEARCredentialMachine();
//        when(objectMapper.convertValue(vcJsonNode, LEARCredentialMachineV1.class)).thenReturn(credential);
//
//        when(jwtService.generateJWT(anyString())).thenReturn("mock-jwt-token");
//
//        // Act
//        Authentication result = customAuthenticationProvider.authenticate(authenticationToken);
//
//        // Assert
//        assertNotNull(result);
//        assertInstanceOf(OAuth2AccessTokenAuthenticationToken.class, result);
//
//        OAuth2AccessTokenAuthenticationToken tokenResult = (OAuth2AccessTokenAuthenticationToken) result;
//        assertEquals("mock-jwt-token", tokenResult.getAccessToken().getTokenValue());
//
//        verify(jwtService, times(1)).generateJWT(anyString());
//
//        verifyNoInteractions(cacheStoreForRefreshTokenData);
//
//        verifyNoInteractions(oAuth2AuthorizationService);
//    }



    @Test
    void authenticate_throw_OAuth2AuthenticationException() {
        Authentication invalidAuthentication = new UsernamePasswordAuthenticationToken("user", "password");

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(invalidAuthentication));

        assertEquals(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE, exception.getError().getErrorCode());
    }

    @Test
    void authenticate_OAuth2ClientCredentialsAuthenticationToken_with_null_additional_parameters_throw_OAuth2AuthenticationException() {

        OAuth2ClientCredentialsAuthenticationToken auth = mock(OAuth2ClientCredentialsAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(null);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
    }

    @Test
    void authenticate_OAuth2AuthorizationCodeAuthenticationToken_with_null_additional_parameters_throw_OAuth2AuthenticationException() {

        OAuth2AuthorizationCodeAuthenticationToken auth = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(null);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
    }

    @Test
    void authenticate_OAuth2ClientCredentialsAuthenticationToken_without_clientId_parameter_throw_OAuth2AuthenticationException() {
        Map<String, Object> additionalParameters = new HashMap<>();

        OAuth2ClientCredentialsAuthenticationToken auth = mock(OAuth2ClientCredentialsAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
    }

    @Test
    void authenticate_OAuth2AuthorizationCodeAuthenticationToken_without_clientId_parameter_throw_OAuth2AuthenticationException() {
        Map<String, Object> additionalParameters = new HashMap<>();

        OAuth2AuthorizationCodeAuthenticationToken auth = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
    }

    @Test
    void authenticate_OAuth2ClientCredentialsAuthenticationToken_with_invalid_registered_client_throw_OAuth2AuthenticationException() {
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("client_id", clientId);

        OAuth2ClientCredentialsAuthenticationToken auth = mock(OAuth2ClientCredentialsAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(null);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, exception.getError().getErrorCode());
    }

    @Test
    void authenticate_OAuth2AuthorizationCodeAuthenticationToken_with_invalid_registered_client_throw_OAuth2AuthenticationException() {
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("client_id", clientId);

        OAuth2AuthorizationCodeAuthenticationToken auth = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(null);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, exception.getError().getErrorCode());
    }

    @Test
    void authenticate_OAuth2ClientCredentialsAuthenticationToken_without_vc_parameter_throw_OAuth2AuthenticationException() {
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("client_id", clientId);

        OAuth2ClientCredentialsAuthenticationToken auth = mock(OAuth2ClientCredentialsAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());

    }

    @Test
    void authenticate_OAuth2AuthorizationCodeAuthenticationToken_without_vc_parameter_throw_OAuth2AuthenticationException() {
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("client_id", clientId);

        OAuth2AuthorizationCodeAuthenticationToken auth = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());

    }

    @Test
    void authenticate_OAuth2AuthorizationCodeAuthenticationToken_without_audience_map_parameter_throws_OAuth2AuthenticationException() {
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("vc", new HashMap<>());
        additionalParameters.put("client_id", clientId);

        OAuth2AuthorizationCodeAuthenticationToken auth = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        JsonNode jsonNode = mock(JsonNode.class);
        when(objectMapper.convertValue(additionalParameters.get("vc"), JsonNode.class)).thenReturn(jsonNode);
        ArrayNode contextNode = JsonNodeFactory.instance.arrayNode();
        for (String ctx : LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT) {
            contextNode.add(ctx);
        }
        when(jsonNode.get("@context")).thenReturn(contextNode);

        LEARCredentialEmployeeV1 credential = getLEARCredentialEmployeeV1();
        when(objectMapper.convertValue(any(), eq(LEARCredentialEmployeeV1.class))).thenReturn(credential);


        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class, () -> customAuthenticationProvider.authenticate(auth));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
    }

    @Test
    void authenticate_withProfileAndEmailScopes_addsCorrespondingClaims() throws Exception {
        // Given
        String clientId = "test-client-id";
        String audience = "test-audience";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("vc", new HashMap<>());
        additionalParameters.put("client_id", clientId);
        additionalParameters.put("audience", audience);
        additionalParameters.put(OAuth2ParameterNames.SCOPE, "openid profile email");

        OAuth2AuthorizationCodeAuthenticationToken auth = mock(OAuth2AuthorizationCodeAuthenticationToken.class);
        when(auth.getAdditionalParameters()).thenReturn(additionalParameters);

        // Mock principal
        TestingAuthenticationToken principal = new TestingAuthenticationToken("test-user", null);
        when(auth.getPrincipal()).thenReturn(principal);

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
        when(registeredClient.getClientId()).thenReturn(clientId);
        when(registeredClient.getId()).thenReturn("registered-client-id");

        when(backendConfig.getUrl()).thenReturn("https://auth.server");

        // Mock verifiable credential
        JsonNode jsonNode = mock(JsonNode.class);
        when(objectMapper.convertValue(additionalParameters.get("vc"), JsonNode.class)).thenReturn(jsonNode);
        ArrayNode contextNode = JsonNodeFactory.instance.arrayNode();
        for (String ctx : LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT) {
            contextNode.add(ctx);
        }
        when(jsonNode.get("@context")).thenReturn(contextNode);

        LEARCredentialEmployeeV1 credential = getLEARCredentialEmployeeV1();
        when(objectMapper.convertValue(any(), eq(LEARCredentialEmployeeV1.class))).thenReturn(credential);
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"value\"}");

        ArgumentCaptor<String> jwtPayloadCaptor = ArgumentCaptor.forClass(String.class);
        when(jwtService.generateJWT(jwtPayloadCaptor.capture())).thenReturn("mock-jwt-token");

        // When
        Authentication result = customAuthenticationProvider.authenticate(auth);

        // Then
        assertNotNull(result);
        assertInstanceOf(OAuth2AccessTokenAuthenticationToken.class, result);

        OAuth2AccessTokenAuthenticationToken tokenResult = (OAuth2AccessTokenAuthenticationToken) result;
        assertEquals("mock-jwt-token", tokenResult.getAccessToken().getTokenValue());

        Map<String, Object> additionalParams = tokenResult.getAdditionalParameters();
        assertTrue(additionalParams.containsKey("id_token"));
        assertEquals("mock-jwt-token", additionalParams.get("id_token"));

        verify(jwtService, times(2)).generateJWT(any());

        List<String> capturedPayloads = jwtPayloadCaptor.getAllValues();
        assertEquals(2, capturedPayloads.size());

        String idTokenPayloadString = capturedPayloads.get(1);
        ObjectMapper objectMapperUtil = new ObjectMapper();
        Map<String, Object> idTokenClaims = objectMapperUtil.readValue(idTokenPayloadString, Map.class);

        assertEquals("did:key:1234", idTokenClaims.get("sub"));
        assertEquals("https://auth.server", idTokenClaims.get("iss"));
        assertEquals(audience, idTokenClaims.get("aud"));

        assertEquals("John Doe", idTokenClaims.get("name"));
        assertEquals("John", idTokenClaims.get("given_name"));
        assertEquals("Doe", idTokenClaims.get("family_name"));

        assertEquals("john.doe@example.com", idTokenClaims.get("email"));
        assertEquals(true, idTokenClaims.get("email_verified"));

        ArgumentCaptor<String> refreshTokenCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<RefreshTokenDataCache> refreshTokenDataCaptor = ArgumentCaptor.forClass(RefreshTokenDataCache.class);
        verify(cacheStoreForRefreshTokenData).add(refreshTokenCaptor.capture(), refreshTokenDataCaptor.capture());

        ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(oAuth2AuthorizationService).save(authorizationCaptor.capture());

        OAuth2Authorization authorization = authorizationCaptor.getValue();
        assertNotNull(authorization);
        assertEquals(clientId, authorization.getPrincipalName());

        if (additionalParameters.containsKey("nonce")) {
            assertEquals(additionalParameters.get("nonce"), idTokenClaims.get("nonce"));
        }
    }



    @Test
    void supports_returnsTrue_forAuthorizationCodeAuthenticationToken() {
        boolean result = customAuthenticationProvider.supports(OAuth2AuthorizationCodeAuthenticationToken.class);
        assertTrue(result);
    }

    @Test
    void supports_returnsTrue_forClientCredentialsAuthenticationToken() {
        boolean result = customAuthenticationProvider.supports(OAuth2ClientCredentialsAuthenticationToken.class);
        assertTrue(result);
    }

    @Test
    void supports_returnsFalse_forOtherAuthenticationToken() {
        boolean result = customAuthenticationProvider.supports(OAuth2AccessTokenAuthenticationToken.class);
        assertFalse(result);
    }

    @Test
    void supports_returnsFalse_forNonAuthenticationClass() {
        boolean result = customAuthenticationProvider.supports(String.class);
        assertFalse(result);
    }


    private LEARCredentialEmployeeV1 getLEARCredentialEmployeeV1(){
        MandateeV1 mandateeV1 = MandateeV1.builder()
                .id("did:key:1234")
                .firstName("John")
                .lastName("Doe")
                .email("john.doe@example.com")
                .build();
        MandateV1 mandate = MandateV1.builder()
                .mandatee(mandateeV1)
                .build();
        es.in2.vcverifier.model.credentials.lear.employee.subject.CredentialSubjectV1 credentialSubjectV1 = es.in2.vcverifier.model.credentials.lear.employee.subject.CredentialSubjectV1.builder()
                .mandate(mandate)
                .build();
        return LEARCredentialEmployeeV1.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .context(LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT)
                .id("urn:uuid:1234")
                .issuer(SimpleIssuer.builder()
                        .id("did:elsi:issuer")
                        .build())
                .credentialSubjectV1(credentialSubjectV1)
                .build();
    }

    private LEARCredentialEmployeeV2 getLEARCredentialEmployeeV2(){
        MandateeV2 mandatee = MandateeV2.builder()
                .id("did:key:1234")
                .firstName("John")
                .lastName("Doe")
                .firstNameV1("John")
                .lastNameV1("Doe")
                .nationality("ES")
                .email("john.doe@example.com")
                .build();
        PowerV2 power = PowerV2.builder()
                .id("power-id")
                .type("Example")
                .tmfType("Example")
                .build();
        MandateV2 mandate = MandateV2.builder()
                .mandatee(mandatee)
                .power(List.of(power))
                .build();
        CredentialSubjectV2 credentialSubject = CredentialSubjectV2.builder()
                .mandate(mandate)
                .build();
        return LEARCredentialEmployeeV2.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .context(LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT)
                .id("urn:uuid:1234")
                .issuer(DetailedIssuer.builder()
                        .id("did:elsi:issuer")
                        .build())
                .credentialSubjectV2(credentialSubject)
                .build();
    }

    @Test
    void authenticate_validClientCredentialsGrant_withMachineCredentialV2_success() {
        // Arrange
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);

        Map<String, Object> vcMap = new HashMap<>();
        vcMap.put("type", List.of("VerifiableCredential", "LEARCredentialMachine"));
        additionalParameters.put("vc", vcMap);

        OAuth2ClientCredentialsAuthenticationToken authenticationToken = mock(OAuth2ClientCredentialsAuthenticationToken.class);
        when(authenticationToken.getAdditionalParameters()).thenReturn(additionalParameters);

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        when(backendConfig.getUrl()).thenReturn("https://auth.server");

        // Mock VC JSON i @context = MACHINE_V2
        JsonNode vcJsonNode = mock(JsonNode.class);
        when(objectMapper.convertValue(vcMap, JsonNode.class)).thenReturn(vcJsonNode);
        ArrayNode contextNode = JsonNodeFactory.instance.arrayNode();
        for (String ctx : LEAR_CREDENTIAL_MACHINE_V2_CONTEXT) {
            contextNode.add(ctx);
        }
        when(vcJsonNode.get("@context")).thenReturn(contextNode);

        // Mock credencial V2
        LEARCredentialMachineV2 machineV2 = mock(LEARCredentialMachineV2.class);
        when(machineV2.type()).thenReturn(List.of("VerifiableCredential", "LEARCredentialMachine"));
        when(machineV2.context()).thenReturn(LEAR_CREDENTIAL_MACHINE_V2_CONTEXT);
        when(objectMapper.convertValue(vcJsonNode, LEARCredentialMachineV2.class)).thenReturn(machineV2);

        // quan es mapegi la credencial a Map per inserir-la a les claims
        when(objectMapper.convertValue(eq(machineV2), any(TypeReference.class))).thenReturn(Map.of("dummy", "value"));

        when(jwtService.generateJWT(anyString())).thenReturn("mock-jwt-token");

        // Act
        Authentication result = customAuthenticationProvider.authenticate(authenticationToken);

        // Assert
        assertNotNull(result);
        assertInstanceOf(OAuth2AccessTokenAuthenticationToken.class, result);

        OAuth2AccessTokenAuthenticationToken tokenResult = (OAuth2AccessTokenAuthenticationToken) result;
        assertEquals("mock-jwt-token", tokenResult.getAccessToken().getTokenValue());

        // En client credentials NO hi ha id_token ni refresh
        assertTrue(tokenResult.getAdditionalParameters().isEmpty());

        verify(jwtService, times(1)).generateJWT(anyString());
        verifyNoInteractions(cacheStoreForRefreshTokenData);
        verifyNoInteractions(oAuth2AuthorizationService);
    }

    @Test
    void authenticate_validClientCredentialsGrant_withMachineCredentialV1_success() {
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);

        Map<String, Object> vcMap = new HashMap<>();
        vcMap.put("type", List.of("VerifiableCredential", "LEARCredentialMachine"));
        additionalParameters.put("vc", vcMap);

        OAuth2ClientCredentialsAuthenticationToken authenticationToken = mock(OAuth2ClientCredentialsAuthenticationToken.class);
        when(authenticationToken.getAdditionalParameters()).thenReturn(additionalParameters);

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        when(backendConfig.getUrl()).thenReturn("https://auth.server");

        // @context qualsevol que NO sigui LEAR_CREDENTIAL_MACHINE_V2_CONTEXT
        JsonNode vcJsonNode = mock(JsonNode.class);
        when(objectMapper.convertValue(vcMap, JsonNode.class)).thenReturn(vcJsonNode);
        ArrayNode contextNode = JsonNodeFactory.instance.arrayNode();
        contextNode.add("https://any.other/context"); // diferent de V2
        when(vcJsonNode.get("@context")).thenReturn(contextNode);

        LEARCredentialMachineV1 machineV1 = mock(LEARCredentialMachineV1.class);
        when(machineV1.type()).thenReturn(List.of("VerifiableCredential", "LEARCredentialMachine"));
        // Important: que el context de la credencial retornada tampoc sigui igual a V2
        when(machineV1.context()).thenReturn(List.of("https://any.other/context"));
        when(objectMapper.convertValue(vcJsonNode, LEARCredentialMachineV1.class)).thenReturn(machineV1);

        when(objectMapper.convertValue(eq(machineV1), any(TypeReference.class))).thenReturn(Map.of("dummy", "value"));
        when(jwtService.generateJWT(anyString())).thenReturn("mock-jwt-token");

        Authentication result = customAuthenticationProvider.authenticate(authenticationToken);

        assertNotNull(result);
        assertInstanceOf(OAuth2AccessTokenAuthenticationToken.class, result);
        OAuth2AccessTokenAuthenticationToken tokenResult = (OAuth2AccessTokenAuthenticationToken) result;
        assertEquals("mock-jwt-token", tokenResult.getAccessToken().getTokenValue());
        assertTrue(tokenResult.getAdditionalParameters().isEmpty());

        verify(jwtService, times(1)).generateJWT(anyString());
        verifyNoInteractions(cacheStoreForRefreshTokenData);
        verifyNoInteractions(oAuth2AuthorizationService);
    }



//    private LEARCredentialMachineV1 getLEARCredentialMachine(){
//        MandateeV1 mandatee = MandateeV1.builder().id("mandatee-id").build();
//        MandateV1 mandateLCEmployee = es.in2.vcverifier.model.credentials.lear.machine.subject.mandate.MandateV1.builder().mandatee(mandatee).build();
//        CredentialSubjectV1 credentialSubjectV1 = new CredentialSubjectV1(mandateLCEmployee);
//
//        return LEARCredentialMachineV1.builder()
//                .credentialSubjectV1(credentialSubjectV1)
//                .context(List.of("https://www.w3.org/2018/credentials/v1"))
//                .id("urn:uuid:1234")
//                .issuer(DetailedIssuer.builder()
//                        .id("did:elsi:issuer")
//                        .build())
//                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
//                .build();
//    }

    @Test
    void authenticate_publicClient_withValidPkce_succeeds() throws Exception {
        String clientId = "public-client";
        String audience = "api";
        String code = "auth-code-1";
        String verifier = "my_verifier_123";
        String challenge = s256(verifier);

        Map<String, Object> additional = new HashMap<>();
        additional.put(OAuth2ParameterNames.CLIENT_ID, clientId);
        additional.put(OAuth2ParameterNames.AUDIENCE, audience);
        additional.put(OAuth2ParameterNames.SCOPE, "openid");
        additional.put("vc", Map.of("@context", LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT));
        additional.put(PkceParameterNames.CODE_VERIFIER, verifier);

        Authentication clientPrincipal = new TestingAuthenticationToken(clientId, null);

        OAuth2AuthorizationCodeAuthenticationToken authToken =
                new OAuth2AuthorizationCodeAuthenticationToken(code, clientPrincipal, null, additional);

        RegisteredClient rc = mock(RegisteredClient.class);
        when(rc.getClientAuthenticationMethods())
                .thenReturn(Set.of(ClientAuthenticationMethod.NONE));
        when(rc.getClientSettings())
                .thenReturn(ClientSettings.builder().requireProofKey(true).build());
        when(rc.getClientId()).thenReturn(clientId);
        when(rc.getId()).thenReturn("rc-id");
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(rc);

        OAuth2Authorization stored = OAuth2Authorization.withRegisteredClient(rc)
                .id("auth-id")
                .principalName(clientId)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(OAuth2ParameterNames.CLIENT_ID, clientId)
                .attribute(PkceParameterNames.CODE_CHALLENGE, challenge)
                .attribute(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256")
                .build();
        when(oAuth2AuthorizationService.findByToken(eq(code), any(OAuth2TokenType.class)))
                .thenReturn(stored);

        JsonNode vcJson = mock(JsonNode.class);
        ArrayNode ctx = JsonNodeFactory.instance.arrayNode();
        for (String c : LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT) ctx.add(c);
        when(vcJson.get("@context")).thenReturn(ctx);

        when(objectMapper.convertValue(any(), eq(JsonNode.class))).thenReturn(vcJson);

        LEARCredentialEmployeeV1 vc = getLEARCredentialEmployeeV1();

        when(objectMapper.convertValue(ArgumentMatchers.<LEARCredential>any(), eq(LEARCredentialEmployeeV1.class)))
                .thenReturn(vc);

        doReturn(Map.of("dummy", "value"))
                .when(objectMapper)
                .convertValue(any(LEARCredentialEmployeeV1.class), any(TypeReference.class));

        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"value\"}");

        when(backendConfig.getUrl()).thenReturn("https://auth.server");

        when(jwtService.generateJWT(anyString())).thenReturn("jwt-access", "jwt-id");

        Authentication result = customAuthenticationProvider.authenticate(authToken);

        assertNotNull(result);
        assertInstanceOf(OAuth2AccessTokenAuthenticationToken.class, result);
        OAuth2AccessTokenAuthenticationToken tr = (OAuth2AccessTokenAuthenticationToken) result;
        assertEquals("jwt-access", tr.getAccessToken().getTokenValue());
        assertEquals("jwt-id", tr.getAdditionalParameters().get("id_token"));

        verify(oAuth2AuthorizationService, atLeastOnce()).remove(stored);
    }

    private static String s256(String verifier) throws Exception {
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(verifier.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }




}