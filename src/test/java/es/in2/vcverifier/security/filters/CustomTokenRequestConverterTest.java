package es.in2.vcverifier.security.filters;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.exception.UnsupportedGrantTypeException;
import es.in2.vcverifier.model.AuthorizationCodeData;
import es.in2.vcverifier.model.credentials.lear.machine.LEARCredentialMachineV1;
import es.in2.vcverifier.model.enums.LEARCredentialType;
import es.in2.vcverifier.service.ClientAssertionValidationService;
import es.in2.vcverifier.service.JWTService;
import es.in2.vcverifier.service.VpService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hibernate.validator.internal.util.Contracts.assertNotNull;
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
    private OAuth2AuthorizationService oAuth2AuthorizationService;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private CustomTokenRequestConverter customTokenRequestConverter;

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
    void convert_clientCredentialsGrant_success(){
        // Arrange
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        Authentication clientPrincipal = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(clientPrincipal);

        String clientId = "client-id";
        String clientAssertion = "client-assertion";
        String rawVpToken = "vp-token";
        // Encoded VP token (base64)
        String encodedVpToken = Base64.getEncoder().encodeToString(rawVpToken.getBytes(StandardCharsets.UTF_8));

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "client_credentials");
        parameters.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        parameters.add(OAuth2ParameterNames.CLIENT_ASSERTION, clientAssertion);

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));

        // Mock del JWTService
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(clientAssertion)).thenReturn(signedJWT);
        when(jwtService.getPayloadFromSignedJWT(signedJWT)).thenReturn(payload);
        when(jwtService.getClaimFromPayload(payload, "vp_token")).thenReturn(encodedVpToken);

        JsonNode mockVC = mock(JsonNode.class);

        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(rawVpToken)).thenReturn(mockVC);

        when(clientAssertionValidationService.validateClientAssertionJWTClaims(clientId, payload)).thenReturn(true);

        LEARCredentialMachineV1 learCredentialMachine = mock(LEARCredentialMachineV1.class);
        when(objectMapper.convertValue(mockVC, LEARCredentialMachineV1.class)).thenReturn(learCredentialMachine);
        when(learCredentialMachine.type()).thenReturn(List.of(LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue()));

        // Act
        Authentication result = customTokenRequestConverter.convert(mockRequest);

        // Assert
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
        // Encoded VP token (base64)
        String encodedVpToken = Base64.getEncoder().encodeToString(rawVpToken.getBytes(StandardCharsets.UTF_8));
        when(jwtService.getClaimFromPayload(any(), eq("vp_token"))).thenReturn(encodedVpToken);

        JsonNode mockVC = mock(JsonNode.class);
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(anyString())).thenReturn(mockVC);

        LEARCredentialMachineV1 learCredentialMachine = mock(LEARCredentialMachineV1.class);
        when(objectMapper.convertValue(mockVC, LEARCredentialMachineV1.class)).thenReturn(learCredentialMachine);
        when(learCredentialMachine.type()).thenReturn(List.of(LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue()));

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
        // Encoded VP token (base64)
        String encodedVpToken = Base64.getEncoder().encodeToString(rawVpToken.getBytes(StandardCharsets.UTF_8));
        when(jwtService.getClaimFromPayload(any(), eq("vp_token"))).thenReturn(encodedVpToken);

        JsonNode mockVC = mock(JsonNode.class);
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(anyString())).thenReturn(mockVC);

        LEARCredentialMachineV1 learCredentialMachine = mock(LEARCredentialMachineV1.class);
        when(objectMapper.convertValue(mockVC, LEARCredentialMachineV1.class)).thenReturn(learCredentialMachine);
        when(learCredentialMachine.type()).thenReturn(List.of(LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue()));

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
        // Encoded VP token (base64)
        String encodedVpToken = Base64.getEncoder().encodeToString(rawVpToken.getBytes(StandardCharsets.UTF_8));
        when(jwtService.getClaimFromPayload(any(), eq("vp_token"))).thenReturn(encodedVpToken);

        // Mock the behavior of getCredentialFromTheVerifiablePresentationAsJsonNode with the correct vpToken
        JsonNode mockVC = mock(JsonNode.class);
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(rawVpToken)).thenReturn(mockVC);

        LEARCredentialMachineV1 learCredentialMachine = mock(LEARCredentialMachineV1.class);
        when(objectMapper.convertValue(mockVC, LEARCredentialMachineV1.class)).thenReturn(learCredentialMachine);

        // Simulate an invalid LEARCredentialType
        when(learCredentialMachine.type()).thenReturn(List.of("InvalidType"));

        // Verify the exception is thrown
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

    // Helper method to convert MultiValueMap to a regular Map for the request mock
    private Map<String, String[]> convertToMap(MultiValueMap<String, String> multiValueMap) {
        Map<String, String[]> map = new HashMap<>();
        multiValueMap.forEach((key, valueList) -> map.put(key, valueList.toArray(new String[0])));
        return map;
    }

}