package es.in2.vcverifier.oauth2.infrastructure.filter;

import es.in2.vcverifier.oauth2.infrastructure.filter.CustomTokenRequestConverter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.oauth2.application.workflow.ClientCredentialsValidationWorkflow;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.oauth2.domain.exception.UnsupportedGrantTypeException;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationCodeData;
import es.in2.vcverifier.oauth2.domain.model.RefreshTokenDataCache;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomTokenRequestConverterTest {

    @Mock
    private ClientCredentialsValidationWorkflow clientCredentialsValidationWorkflow;

    @Mock
    private CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;

    @Mock
    private CacheStore<RefreshTokenDataCache> refreshTokenDataCacheCacheStore;

    private CustomTokenRequestConverter customTokenRequestConverter;

    @BeforeEach
    void setUp() {
        customTokenRequestConverter = new CustomTokenRequestConverter(
                clientCredentialsValidationWorkflow,
                cacheStoreForAuthorizationCodeData,
                refreshTokenDataCacheCacheStore
        );
    }

    @Test
    void convert_authorizationCodeGrant_shouldReturnOAuth2AuthorizationCodeAuthenticationToken() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        Authentication clientPrincipal = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(clientPrincipal);

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "authorization_code");
        parameters.add(OAuth2ParameterNames.CODE, "code");
        parameters.add(OAuth2ParameterNames.CLIENT_ID, "client-id");
        parameters.add(OAuth2ParameterNames.STATE, "state");

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));
        AuthorizationCodeData authorizationCodeData = mock(AuthorizationCodeData.class);
        when(cacheStoreForAuthorizationCodeData.get("code")).thenReturn(authorizationCodeData);
        when(authorizationCodeData.state()).thenReturn("state");

        JsonNode jsonNodeMock = mock(JsonNode.class);
        when(authorizationCodeData.verifiableCredential()).thenReturn(jsonNodeMock);

        Authentication result = customTokenRequestConverter.convert(mockRequest);

        assertNotNull(result);
        assertInstanceOf(OAuth2AuthorizationCodeAuthenticationToken.class, result);
    }

    @Test
    void convert_clientCredentialsGrant_success() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        Authentication clientPrincipal = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(clientPrincipal);

        String clientId = "client-id";
        String clientAssertion = "client-assertion";

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "client_credentials");
        parameters.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        parameters.add(OAuth2ParameterNames.CLIENT_ASSERTION, clientAssertion);

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));

        JsonNode mockVC = buildMachineCredentialJsonNode();
        when(clientCredentialsValidationWorkflow.execute(clientId, clientAssertion)).thenReturn(mockVC);

        Authentication result = customTokenRequestConverter.convert(mockRequest);

        assertNotNull(result);
        assertInstanceOf(OAuth2ClientCredentialsAuthenticationToken.class, result);

        OAuth2ClientCredentialsAuthenticationToken token = (OAuth2ClientCredentialsAuthenticationToken) result;
        assertEquals(clientPrincipal, token.getPrincipal());

        Map<String, Object> additionalParameters = token.getAdditionalParameters();
        assertEquals(clientId, additionalParameters.get(OAuth2ParameterNames.CLIENT_ID));
    }

    @Test
    void convert_clientCredentialsGrant_shouldReturnIllegalArgumentException_Invalid_JWT_claims_from_assertion() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        Authentication clientPrincipal = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(clientPrincipal);

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "client_credentials");
        parameters.add(OAuth2ParameterNames.CLIENT_ID, "client-id");
        parameters.add(OAuth2ParameterNames.CLIENT_ASSERTION, "client-assertion");

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));
        when(clientCredentialsValidationWorkflow.execute("client-id", "client-assertion"))
                .thenThrow(new IllegalArgumentException("Invalid JWT claims from assertion"));

        assertThrows(IllegalArgumentException.class, () ->
                customTokenRequestConverter.convert(mockRequest));
    }

    @Test
    void convert_clientCredentialsGrant_shouldReturnRuntimeException_Invalid_VP_Token() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        Authentication clientPrincipal = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(clientPrincipal);

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "client_credentials");
        parameters.add(OAuth2ParameterNames.CLIENT_ID, "client-id");
        parameters.add(OAuth2ParameterNames.CLIENT_ASSERTION, "client-assertion");

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));
        when(clientCredentialsValidationWorkflow.execute("client-id", "client-assertion"))
                .thenThrow(new RuntimeException("Something failed"));

        assertThrows(RuntimeException.class, () ->
                customTokenRequestConverter.convert(mockRequest));
    }

    @Test
    void handleClientCredentialsGrant_invalidCredentialType_shouldThrowInvalidCredentialTypeException() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        Authentication clientPrincipal = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(clientPrincipal);

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "client_credentials");
        parameters.add(OAuth2ParameterNames.CLIENT_ID, "client-id");
        parameters.add(OAuth2ParameterNames.CLIENT_ASSERTION, "client-assertion");

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));
        when(clientCredentialsValidationWorkflow.execute("client-id", "client-assertion"))
                .thenThrow(new InvalidCredentialTypeException("Invalid LEARCredentialType. Expected LEARCredentialMachine"));

        assertThrows(InvalidCredentialTypeException.class, () ->
                customTokenRequestConverter.convert(mockRequest));
    }

    @Test
    void convert_unsupportedGrantType_shouldThrowUnsupportedGrantTypeException() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "invalid_grant_type");

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));

        assertThrows(UnsupportedGrantTypeException.class, () ->
                customTokenRequestConverter.convert(mockRequest));
    }

    private JsonNode buildMachineCredentialJsonNode() {
        JsonNodeFactory factory = JsonNodeFactory.instance;
        ArrayNode typeArray = factory.arrayNode();
        typeArray.add("VerifiableCredential");
        typeArray.add("LEARCredentialMachine");
        return factory.objectNode().set("type", typeArray);
    }

    private Map<String, String[]> convertToMap(MultiValueMap<String, String> multiValueMap) {
        Map<String, String[]> map = new HashMap<>();
        multiValueMap.forEach((key, valueList) -> map.put(key, valueList.toArray(new String[0])));
        return map;
    }
}
