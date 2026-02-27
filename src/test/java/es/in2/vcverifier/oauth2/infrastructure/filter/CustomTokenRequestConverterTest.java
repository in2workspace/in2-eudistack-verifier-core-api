package es.in2.vcverifier.oauth2.infrastructure.filter;
import es.in2.vcverifier.security.filters.CustomTokenRequestConverter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.oauth2.domain.exception.UnsupportedGrantTypeException;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationCodeData;
import es.in2.vcverifier.oauth2.domain.model.RefreshTokenDataCache;
import es.in2.vcverifier.service.ClientAssertionValidationService;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.verifier.domain.service.VpService;
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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomTokenRequestConverterTest {

    @Mock
    private JWTService jwtService;

    @Mock
    private ClientAssertionValidationService clientAssertionValidationService;

    @Mock
    private VpService vpService;

    @Mock
    private CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;

    @Mock
    private CacheStore<RefreshTokenDataCache> refreshTokenDataCacheCacheStore;

    private CustomTokenRequestConverter customTokenRequestConverter;

    private final ObjectMapper realObjectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        customTokenRequestConverter = new CustomTokenRequestConverter(
                jwtService,
                clientAssertionValidationService,
                vpService,
                cacheStoreForAuthorizationCodeData,
                refreshTokenDataCacheCacheStore
        );
    }

    @Test
    void convert_authorizationCodeGrant_shouldReturnOAuth2ClientCredentialsAuthenticationToken() {
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
        String rawVpToken = "vp-token";
        String encodedVpToken = Base64.getEncoder().encodeToString(rawVpToken.getBytes(StandardCharsets.UTF_8));

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "client_credentials");
        parameters.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        parameters.add(OAuth2ParameterNames.CLIENT_ASSERTION, clientAssertion);

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));

        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(clientAssertion)).thenReturn(signedJWT);
        when(jwtService.getPayloadFromSignedJWT(signedJWT)).thenReturn(payload);
        when(jwtService.getClaimFromPayload(payload, "vp_token")).thenReturn(encodedVpToken);

        // Build a JsonNode with type array containing LEARCredentialMachine
        JsonNode mockVC = buildMachineCredentialJsonNode();
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(rawVpToken)).thenReturn(mockVC);
        when(clientAssertionValidationService.validateClientAssertionJWTClaims(clientId, payload)).thenReturn(true);

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

        SignedJWT signedJWT = mock(SignedJWT.class);
        when(jwtService.parseJWT("client-assertion")).thenReturn(signedJWT);

        String rawVpToken = "vp-token";
        String encodedVpToken = Base64.getEncoder().encodeToString(rawVpToken.getBytes(StandardCharsets.UTF_8));
        when(jwtService.getClaimFromPayload(any(), eq("vp_token"))).thenReturn(encodedVpToken);

        JsonNode mockVC = buildMachineCredentialJsonNode();
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(anyString())).thenReturn(mockVC);

        when(clientAssertionValidationService.validateClientAssertionJWTClaims(anyString(), any())).thenReturn(false);

        assertThrows(IllegalArgumentException.class, () ->
                customTokenRequestConverter.convert(mockRequest));
    }

    @Test
    void convert_clientCredentialsGrant_shouldReturnIllegalArgumentException_Invalid_VP_Token() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        Authentication clientPrincipal = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(clientPrincipal);

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "client_credentials");
        parameters.add(OAuth2ParameterNames.CLIENT_ID, "client-id");
        parameters.add(OAuth2ParameterNames.CLIENT_ASSERTION, "client-assertion");

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));

        SignedJWT signedJWT = mock(SignedJWT.class);
        when(jwtService.parseJWT("client-assertion")).thenReturn(signedJWT);

        String rawVpToken = "vp-token";
        String encodedVpToken = Base64.getEncoder().encodeToString(rawVpToken.getBytes(StandardCharsets.UTF_8));
        when(jwtService.getClaimFromPayload(any(), eq("vp_token"))).thenReturn(encodedVpToken);

        JsonNode mockVC = buildMachineCredentialJsonNode();
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(anyString())).thenReturn(mockVC);

        when(clientAssertionValidationService.validateClientAssertionJWTClaims(anyString(), any())).thenReturn(true);
        doThrow(new RuntimeException("Something failed")).when(vpService).validateVerifiablePresentation(anyString());

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

        SignedJWT signedJWT = mock(SignedJWT.class);
        when(jwtService.parseJWT("client-assertion")).thenReturn(signedJWT);

        String rawVpToken = "vp-token";
        String encodedVpToken = Base64.getEncoder().encodeToString(rawVpToken.getBytes(StandardCharsets.UTF_8));
        when(jwtService.getClaimFromPayload(any(), eq("vp_token"))).thenReturn(encodedVpToken);

        // Build a VC with an invalid type
        JsonNode mockVC = buildCredentialJsonNode("InvalidType");
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(rawVpToken)).thenReturn(mockVC);

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
        return buildCredentialJsonNode("LEARCredentialMachine");
    }

    private JsonNode buildCredentialJsonNode(String credentialType) {
        JsonNodeFactory factory = JsonNodeFactory.instance;
        ArrayNode typeArray = factory.arrayNode();
        typeArray.add("VerifiableCredential");
        typeArray.add(credentialType);

        return factory.objectNode().set("type", typeArray);
    }

    private Map<String, String[]> convertToMap(MultiValueMap<String, String> multiValueMap) {
        Map<String, String[]> map = new HashMap<>();
        multiValueMap.forEach((key, valueList) -> map.put(key, valueList.toArray(new String[0])));
        return map;
    }
}
