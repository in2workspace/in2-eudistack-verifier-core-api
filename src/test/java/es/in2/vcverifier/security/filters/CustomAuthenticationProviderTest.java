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
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV1;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV2;
import es.in2.vcverifier.model.credentials.lear.employee.subject.CredentialSubjectV1;
import es.in2.vcverifier.model.credentials.lear.employee.subject.CredentialSubjectV2;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.MandateV1;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.MandateV2;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.mandatee.MandateeV1;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.mandatee.MandateeV2;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.power.PowerV2;
import es.in2.vcverifier.model.credentials.lear.machine.LEARCredentialMachine;
import es.in2.vcverifier.model.credentials.lear.machine.subject.CredentialSubject;
import es.in2.vcverifier.model.credentials.lear.machine.subject.mandate.Mandate;
import es.in2.vcverifier.model.credentials.lear.machine.subject.mandate.mandatee.Mandatee;
import es.in2.vcverifier.service.JWTService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    @Test
    void authenticate_validClientCredentialsGrant_withMachineCredential_success() throws Exception {
        // Arrange
        String clientId = "test-client-id";
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("client_id", clientId);

        Map<String, Object> vcMap = new HashMap<>();
        vcMap.put("type", List.of("VerifiableCredential", "LEARCredentialMachine"));

        additionalParameters.put("vc", vcMap);
        additionalParameters.put(OAuth2ParameterNames.SCOPE, "machine");

        OAuth2ClientCredentialsAuthenticationToken authenticationToken = mock(OAuth2ClientCredentialsAuthenticationToken.class);
        when(authenticationToken.getAdditionalParameters()).thenReturn(additionalParameters);

        TestingAuthenticationToken principal = new TestingAuthenticationToken("test-user", null);
        when(authenticationToken.getPrincipal()).thenReturn(principal);

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
        when(registeredClient.getClientId()).thenReturn(clientId);
        when(registeredClient.getId()).thenReturn("registered-client-id");

        when(backendConfig.getUrl()).thenReturn("https://auth.server");

        JsonNode vcJsonNode = mock(JsonNode.class);
        when(objectMapper.convertValue(vcMap, JsonNode.class)).thenReturn(vcJsonNode);

        LEARCredentialMachine credential = getLEARCredentialMachine();
        when(objectMapper.convertValue(vcJsonNode, LEARCredentialMachine.class)).thenReturn(credential);

        when(objectMapper.writeValueAsString(credential)).thenReturn("{\"credential\":\"value\"}");

        when(jwtService.generateJWT(anyString())).thenReturn("mock-jwt-token");

        // Act
        Authentication result = customAuthenticationProvider.authenticate(authenticationToken);

        // Assert
        assertNotNull(result);
        assertInstanceOf(OAuth2AccessTokenAuthenticationToken.class, result);

        OAuth2AccessTokenAuthenticationToken tokenResult = (OAuth2AccessTokenAuthenticationToken) result;
        assertEquals("mock-jwt-token", tokenResult.getAccessToken().getTokenValue());

        verify(jwtService, times(2)).generateJWT(anyString());

        // Verificar the refresh token data cache
        ArgumentCaptor<String> refreshTokenCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<RefreshTokenDataCache> refreshTokenDataCaptor = ArgumentCaptor.forClass(RefreshTokenDataCache.class);
        verify(cacheStoreForRefreshTokenData).add(refreshTokenCaptor.capture(), refreshTokenDataCaptor.capture());

        ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(oAuth2AuthorizationService).save(authorizationCaptor.capture());

        OAuth2Authorization authorization = authorizationCaptor.getValue();
        assertEquals(clientId, authorization.getPrincipalName());
    }



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
        CredentialSubjectV1 credentialSubject = CredentialSubjectV1.builder()
                .mandate(mandate)
                .build();
        return LEARCredentialEmployeeV1.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .context(LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT)
                .id("urn:uuid:1234")
                .issuer(SimpleIssuer.builder()
                        .id("did:elsi:issuer")
                        .build())
                .credentialSubjectV1(credentialSubject)
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

    private LEARCredentialMachine getLEARCredentialMachine(){
        Mandatee mandatee = Mandatee.builder().id("mandatee-id").build();
        Mandate mandateLCEmployee = Mandate.builder().mandatee(mandatee).build();
        CredentialSubject credentialSubject = new CredentialSubject(mandateLCEmployee);

        return LEARCredentialMachine.builder()
                .credentialSubject(credentialSubject)
                .context(List.of("https://www.w3.org/2018/credentials/v1"))
                .id("urn:uuid:1234")
                .issuer(DetailedIssuer.builder()
                        .id("did:elsi:issuer")
                        .build())
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .build();
    }

}