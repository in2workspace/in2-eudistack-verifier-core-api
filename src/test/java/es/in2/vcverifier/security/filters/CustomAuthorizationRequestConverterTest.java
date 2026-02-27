package es.in2.vcverifier.security.filters;

import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.component.CryptoComponent;
import es.in2.vcverifier.config.BackendConfig;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.model.AuthorizationRequestJWT;
import es.in2.vcverifier.service.DIDService;
import es.in2.vcverifier.service.JWTService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static es.in2.vcverifier.util.Constants.CLIENT_ERROR_ENDPOINT;
import static es.in2.vcverifier.util.Constants.REQUEST_URI;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;

@ExtendWith(MockitoExtension.class)
class CustomAuthorizationRequestConverterTest {

    @Mock
    private DIDService didService;

    @Mock
    private JWTService jwtService;

    @Mock
    private CryptoComponent cryptoComponent;

    @Mock
    private CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;

    @Mock
    private CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;

    @Mock
    private BackendConfig backendConfig;

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @Mock
    private  CacheStore<String> cacheForNonceByState;

    @Mock
    private HttpClient httpClient;

    private boolean isNonceRequiredOnFapiProfile = true;

    private CustomAuthorizationRequestConverter converter;

    @BeforeEach
    void setUp() {
        converter = new CustomAuthorizationRequestConverter(
                didService,
                jwtService,
                cryptoComponent,
                cacheStoreForAuthorizationRequestJWT,
                cacheStoreForOAuth2AuthorizationRequest,
                backendConfig,
                registeredClientRepository,
                isNonceRequiredOnFapiProfile,
                cacheForNonceByState,
                httpClient
        );
    }

    @Test
    void convert_validStandardRequest_shouldThrowRedirectionException() {
        // Arrange
        HttpServletRequest request = mock(HttpServletRequest.class);
        String clientId = "test-client-id";
        String state = "test-state";
        String scope = "learcredential";
        String redirectUri = "https://client.example.com/callback";
        String clientName = "Test Client";
        String clientNonce = "test-nonce";
        List<String> authorizationGrantTypes = List.of("authorization_code");
        Set<String> redirectUris = Set.of(redirectUri);
        stubPkceParamsNull(request);

        when(request.getRequestURL()).thenReturn(new StringBuffer("https://client.example.com/authorize"));
        when(request.getQueryString()).thenReturn("client_id=test-client-id&scope=learcredential&state=test-state");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
        when(request.getParameter(NONCE)).thenReturn(clientNonce);
        when(request.getParameter(REQUEST_URI)).thenReturn(null);
        when(request.getParameter("request")).thenReturn(null);

        RegisteredClient registeredClient = RegisteredClient.withId("1234")
                .clientId(clientId)
                .clientName(clientName)
                .authorizationGrantTypes(grantTypes -> authorizationGrantTypes.forEach(grantType -> grantTypes.add(new AuthorizationGrantType(grantType))))
                .redirectUris(uris -> uris.addAll(redirectUris))
                .build();

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        when(backendConfig.getUrl()).thenReturn("https://auth.server.com");

        // Mock JWT generation
        ECKey ecKey = mock(ECKey.class);
        when(cryptoComponent.getECKey()).thenReturn(ecKey);
        when(ecKey.getKeyID()).thenReturn("key-id");

        // Act & Assert
        OAuth2AuthorizationCodeRequestAuthenticationException exception = assertThrows(
                OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request)
        );

        OAuth2Error error = exception.getError();
        assertEquals("required_external_user_authentication", error.getErrorCode());

        String redirectUrl = error.getUri();
        assertNotNull(redirectUrl);
        assertTrue(redirectUrl.contains("/login?"));
        assertTrue(redirectUrl.contains("authRequest="));
        assertTrue(redirectUrl.contains("state="));
        assertTrue(redirectUrl.contains("homeUri="));
    }

    @Test
    void convert_fapiRequestWithMismatchedClientId_shouldThrowInvalidClientAuthenticationException() {
        // Arrange
        HttpServletRequest request = mock(HttpServletRequest.class);
        String clientId = "test-client-id";
        String state = "test-state";
        String scope = "learcredential";
        String redirectUri = "https://client.example.com/callback";
        String jwt = "mock-jwt-token";
        String clientName = "Test Client";
        String clientNonce = "test-nonce";
        List<String> authorizationGrantTypes = List.of("authorization_code");
        stubPkceParamsNull(request);

        when(request.getRequestURL()).thenReturn(new StringBuffer("https://client.example.com/authorize"));
        when(request.getQueryString()).thenReturn("client_id=test-client-id&scope=learcredential&state=test-state");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
        when(request.getParameter(NONCE)).thenReturn(clientNonce);
        when(request.getParameter(REQUEST_URI)).thenReturn(null);
        when(request.getParameter("request")).thenReturn(jwt);

        RegisteredClient registeredClient = RegisteredClient.withId("1234")
                .clientId(clientId)
                .clientName(clientName)
                .authorizationGrantTypes(grantTypes -> authorizationGrantTypes.forEach(grantType -> grantTypes.add(new AuthorizationGrantType(grantType))))
                .redirectUris(uris -> uris.add(redirectUri))
                .build();

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        // Mock del JWT
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        when(signedJWT.getPayload()).thenReturn(payload);
        when(jwtService.parseJWT(jwt)).thenReturn(signedJWT);

        // Act & Assert
        OAuth2AuthorizationCodeRequestAuthenticationException exception = assertThrows(
                OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request)
        );

        OAuth2Error error = exception.getError();
        assertEquals("invalid_client_authentication", error.getErrorCode());
        assertTrue(error.getDescription().contains("The OAuth 2.0 parameters do not match the JWT claims."));

        String redirectUrl = error.getUri();
        assertNotNull(redirectUrl);
        assertTrue(redirectUrl.contains("/client-error"));
        assertTrue(redirectUrl.contains("errorCode="));
        assertTrue(redirectUrl.contains("errorMessage="));
        assertTrue(redirectUrl.contains("clientUrl="));
        assertTrue(redirectUrl.contains("originalRequestURL="));
    }


    @Test
    void convert_fapiRequestWithInvalidRedirectUri_shouldThrowInvalidClientAuthenticationException() {
        // Arrange
        HttpServletRequest request = mock(HttpServletRequest.class);
        String clientId = "test-client-id";
        String state = "test-state";
        String scope = "learcredential";
        String redirectUri = "https://client.example.com/callback";
        String jwtRedirectUri = "https://malicious.example.com/callback";
        String jwt = "mock-jwt-token";
        String clientName = "Test Client";
        String clientNonce = "test-nonce";
        List<String> authorizationGrantTypes = List.of("authorization_code");
        stubPkceParamsNull(request);

        when(request.getRequestURL()).thenReturn(new StringBuffer("https://client.example.com/authorize"));
        when(request.getQueryString()).thenReturn("client_id=test-client-id&scope=learcredential&state=test-state");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
        when(request.getParameter(NONCE)).thenReturn(clientNonce);
        when(request.getParameter(REQUEST_URI)).thenReturn(null);
        when(request.getParameter("request")).thenReturn(jwt);

        RegisteredClient registeredClient = RegisteredClient.withId("1234")
                .clientId(clientId)
                .clientName(clientName)
                .authorizationGrantTypes(grantTypes -> authorizationGrantTypes.forEach(grantType -> grantTypes.add(new AuthorizationGrantType(grantType))))
                .redirectUris(uris -> uris.add(redirectUri))
                .build();

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        // Mock del JWT
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        when(signedJWT.getPayload()).thenReturn(payload);
        when(jwtService.parseJWT(jwt)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.SCOPE)).thenReturn(scope);

        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.REDIRECT_URI)).thenReturn(jwtRedirectUri);

        // Act & Assert
        OAuth2AuthorizationCodeRequestAuthenticationException exception = assertThrows(
                OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request)
        );

        OAuth2Error error = exception.getError();
        assertEquals("invalid_client_authentication", error.getErrorCode());
        assertTrue(error.getDescription().contains("The redirect_uri does not match any of the registered client's redirect_uris."));

        String redirectUrl = error.getUri();
        assertNotNull(redirectUrl);
        assertTrue(redirectUrl.contains("/client-error"));
        assertTrue(redirectUrl.contains("errorCode="));
        assertTrue(redirectUrl.contains("errorMessage="));
        assertTrue(redirectUrl.contains("clientUrl="));
        assertTrue(redirectUrl.contains("originalRequestURL="));
    }

    @Test
    void convert_fapiRequestWithRequestUri_shouldProcessSuccessfully() throws Exception {
        // Arrange
        HttpServletRequest request = mock(HttpServletRequest.class);
        String clientId = "test-client-id";
        String state = "test-state";
        String scope = "learcredential";
        String redirectUri = "https://client.example.com/callback";
        String requestUri = "https://client.example.com/request.jwt";
        String jwt = "mock-jwt-token";
        String clientName = "Test Client";
        String clientNonce = "test-nonce";
        List<String> authorizationGrantTypes = List.of("authorization_code");

        when(request.getRequestURL()).thenReturn(new StringBuffer("https://client.example.com/authorize"));
        when(request.getQueryString()).thenReturn("client_id=test-client-id&scope=learcredential&state=test-state");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
        when(request.getParameter(NONCE)).thenReturn(clientNonce);
        when(request.getParameter(REQUEST_URI)).thenReturn(requestUri);

        RegisteredClient registeredClient = RegisteredClient.withId("1234")
                .clientId(clientId)
                .clientName(clientName)
                .authorizationGrantTypes(grantTypes -> authorizationGrantTypes.forEach(grantType -> grantTypes.add(new AuthorizationGrantType(grantType))))
                .redirectUris(uris -> uris.add(redirectUri))
                .build();

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        // Mock del HttpResponse usando el httpClient inyectado
        HttpResponse<String> mockHttpResponse = mock(HttpResponse.class);

        // Simulamos la respuesta de httpClient.send()
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(200);
        when(mockHttpResponse.body()).thenReturn(jwt);

        // Mock del JWT
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        when(signedJWT.getPayload()).thenReturn(payload);
        when(jwtService.parseJWT(jwt)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);

        // Mock de la verificación del JWT
        PublicKey publicKey = mock(PublicKey.class);
        when(didService.getPublicKeyFromDid(clientId)).thenReturn(publicKey);
        when(signedJWT.serialize()).thenReturn("serialized-jwt");
        doNothing().when(jwtService).verifyJWTWithECKey(anyString(), eq(publicKey));

        // Mock de la generación del JWT
        ECKey ecKey = mock(ECKey.class);
        when(ecKey.getKeyID()).thenReturn("key-id");
        when(cryptoComponent.getECKey()).thenReturn(ecKey);

        when(backendConfig.getUrl()).thenReturn("https://auth.server.com");

        // Act & Assert
        OAuth2AuthorizationCodeRequestAuthenticationException exception = assertThrows(
                OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request)
        );

        OAuth2Error error = exception.getError();
        assertEquals("required_external_user_authentication", error.getErrorCode());

        String redirectUrl = error.getUri();
        assertNotNull(redirectUrl);
        assertTrue(redirectUrl.contains("/login?"));
        assertTrue(redirectUrl.contains("authRequest="));
        assertTrue(redirectUrl.contains("state="));
        assertTrue(redirectUrl.contains("homeUri="));

        // Verificamos que se almacenó la solicitud de autorización
        verify(cacheStoreForOAuth2AuthorizationRequest).add(eq(state), any(OAuth2AuthorizationRequest.class));
    }

    @Test
    void convert_standardRequest_missingRedirectUri_shouldThrowException() {
        // Arrange
        HttpServletRequest request = mock(HttpServletRequest.class);
        String clientId = "test-client-id";
        String state = "test-state";
        String scope = "openid learcredential";
        String redirectUri = "https://client.example.com/callback";

        when(request.getRequestURL()).thenReturn(new StringBuffer("https://client.example.com/authorize"));
        when(request.getQueryString()).thenReturn("client_id=test-client-id&scope=learcredential&state=test-state");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
        when(request.getParameter(REQUEST_URI)).thenReturn(null);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);

        // Act & Assert
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> converter.convert(request)
        );

        assertEquals(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, exception.getError().getErrorCode());
    }

    @Test
    void convert_standardRequest_unsupportedScope_shouldThrowInvalidClientAuthenticationException() {
        // Arrange
        HttpServletRequest request = mock(HttpServletRequest.class);
        String clientId = "test-client-id";
        String state = "test-state";
        String scope = "unsupported_scope";
        String redirectUri = "https://client.example.com/callback";
        String clientName = "Test Client";
        String clientNonce = "test-nonce";
        List<String> authorizationGrantTypes = List.of("authorization_code");
        stubPkceParamsNull(request);

        when(request.getRequestURL()).thenReturn(new StringBuffer("https://client.example.com/authorize"));
        when(request.getQueryString()).thenReturn("client_id=test-client-id&scope=learcredential&state=test-state");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
        when(request.getParameter(NONCE)).thenReturn(clientNonce);
        when(request.getParameter(REQUEST_URI)).thenReturn(null);
        when(request.getParameter("request")).thenReturn(null);

        RegisteredClient registeredClient = RegisteredClient.withId("1234")
                .clientId(clientId)
                .clientName(clientName)
                .authorizationGrantTypes(grantTypes -> authorizationGrantTypes.forEach(grantType -> grantTypes.add(new AuthorizationGrantType(grantType))))
                .redirectUris(uris -> uris.add(redirectUri))
                .build();

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
        when(backendConfig.getUrl()).thenReturn("https://auth.server.com");

        // Act & Assert
        OAuth2AuthorizationCodeRequestAuthenticationException exception = assertThrows(
                OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request)
        );

        OAuth2Error error = exception.getError();
        assertEquals("invalid_client_authentication", error.getErrorCode());
        assertTrue(error.getDescription().contains("The requested scope does not contain"));

        String redirectUrl = error.getUri();
        assertNotNull(redirectUrl);
        assertTrue(redirectUrl.contains(CLIENT_ERROR_ENDPOINT));
        assertTrue(redirectUrl.contains("errorCode="));
        assertTrue(redirectUrl.contains("errorMessage="));
        assertTrue(redirectUrl.contains("clientUrl="));
    }

    @Test
    void convert_validFAPIRequestWithRequestParameter_shouldProcessSuccessfully() {
        // Arrange
        HttpServletRequest request = mock(HttpServletRequest.class);
        String clientId = "test-client-id";
        String state = "test-state";
        String scope = "learcredential";
        String redirectUri = "https://client.example.com/callback";
        String jwt = "mock-jwt-token"; // The JWT passed in the 'request' parameter
        String clientName = "Test Client";
        String clientNonce = "test-nonce";
        List<String> authorizationGrantTypes = List.of("authorization_code");
        stubPkceParamsNull(request);

        when(request.getRequestURL()).thenReturn(new StringBuffer("https://client.example.com/authorize"));
        when(request.getQueryString()).thenReturn("client_id=test-client-id&scope=learcredential&state=test-state");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
        when(request.getParameter(REQUEST_URI)).thenReturn(null);
        when(request.getParameter(NONCE)).thenReturn(clientNonce);
        when(request.getParameter("request")).thenReturn(jwt);

        RegisteredClient registeredClient = RegisteredClient.withId("1234")
                .clientId(clientId)
                .clientName(clientName)
                .authorizationGrantTypes(grantTypes -> authorizationGrantTypes.forEach(grantType -> grantTypes.add(new AuthorizationGrantType(grantType))))
                .redirectUris(uris -> uris.add(redirectUri))
                .build();

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        // Mock JWT parsing and validation
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        when(signedJWT.getPayload()).thenReturn(payload);
        when(jwtService.parseJWT(jwt)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);

        // Mock public key retrieval and JWT verification
        PublicKey publicKey = mock(PublicKey.class);
        when(didService.getPublicKeyFromDid(clientId)).thenReturn(publicKey);
        when(signedJWT.serialize()).thenReturn("serialized-jwt");
        doNothing().when(jwtService).verifyJWTWithECKey(anyString(), eq(publicKey));

        // Mock JWT generation
        ECKey ecKey = mock(ECKey.class);
        when(ecKey.getKeyID()).thenReturn("key-id");
        when(cryptoComponent.getECKey()).thenReturn(ecKey);

        when(backendConfig.getUrl()).thenReturn("https://auth.server.com");

        // Act & Assert
        OAuth2AuthorizationCodeRequestAuthenticationException exception = assertThrows(
                OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request)
        );

        OAuth2Error error = exception.getError();
        assertEquals("required_external_user_authentication", error.getErrorCode());

        String redirectUrl = error.getUri();
        assertNotNull(redirectUrl);
        assertTrue(redirectUrl.contains("/login?"));
        assertTrue(redirectUrl.contains("authRequest="));
        assertTrue(redirectUrl.contains("state="));
        assertTrue(redirectUrl.contains("homeUri="));

        // Verify that the OAuth2AuthorizationRequest was cached
        verify(cacheStoreForOAuth2AuthorizationRequest).add(eq(state), any(OAuth2AuthorizationRequest.class));
    }

    @Test
    void convert_requestUriResponseNot200_shouldThrowInvalidClientAuthenticationException() throws Exception {
        // Arrange
        HttpServletRequest request = mock(HttpServletRequest.class);
        String clientId = "test-client-id";
        String state = "test-state";
        String scope = "learcredential";
        String redirectUri = "https://client.example.com/callback";
        String requestUri = "https://client.example.com/request.jwt";
        String clientName = "Test Client";
        List<String> authorizationGrantTypes = List.of("authorization_code");

        when(request.getRequestURL()).thenReturn(new StringBuffer("https://client.example.com/authorize"));
        when(request.getQueryString()).thenReturn("client_id=test-client-id&scope=learcredential&state=test-state");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
        when(request.getParameter(REQUEST_URI)).thenReturn(requestUri);


        RegisteredClient registeredClient = RegisteredClient.withId("1234")
                .clientId(clientId)
                .clientName(clientName)
                .authorizationGrantTypes(grantTypes -> authorizationGrantTypes.forEach(grantType -> grantTypes.add(new AuthorizationGrantType(grantType))))
                .redirectUris(uris -> uris.add(redirectUri))
                .build();

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        // Mock del HttpResponse usando el httpClient inyectado
        HttpResponse<String> mockHttpResponse = mock(HttpResponse.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(mockHttpResponse);

        // Act & Assert
        OAuth2AuthorizationCodeRequestAuthenticationException exception = assertThrows(
                OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request)
        );

        OAuth2Error error = exception.getError();
        assertEquals("invalid_client_authentication", error.getErrorCode());
        assertTrue(error.getDescription().contains("Failed to retrieve JWT from request_uri: Invalid response."));

        String redirectUrl = error.getUri();
        assertNotNull(redirectUrl);
        assertTrue(redirectUrl.contains(CLIENT_ERROR_ENDPOINT));
        assertTrue(redirectUrl.contains("errorCode="));
        assertTrue(redirectUrl.contains("errorMessage="));
        assertTrue(redirectUrl.contains("clientUrl="));
    }

    @Test
    void convert_requestUriThrowsIOException_shouldThrowInvalidClientAuthenticationException() throws Exception {
        // Arrange
        HttpServletRequest request = mock(HttpServletRequest.class);
        String clientId = "test-client-id";
        String state = "test-state";
        String scope = "learcredential";
        String redirectUri = "https://client.example.com/callback";
        String requestUri = "https://client.example.com/request.jwt";
        String clientName = "Test Client";
        String clientNonce = "test-nonce";
        List<String> authorizationGrantTypes = List.of("authorization_code");

        when(request.getRequestURL()).thenReturn(new StringBuffer("https://client.example.com/authorize"));
        when(request.getQueryString()).thenReturn("client_id=test-client-id&scope=learcredential&state=test-state");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
        when(request.getParameter(NONCE)).thenReturn(clientNonce);
        when(request.getParameter(REQUEST_URI)).thenReturn(requestUri);

        RegisteredClient registeredClient = RegisteredClient.withId("1234")
                .clientId(clientId)
                .clientName(clientName)
                .authorizationGrantTypes(grantTypes -> authorizationGrantTypes.forEach(grantType -> grantTypes.add(new AuthorizationGrantType(grantType))))
                .redirectUris(uris -> uris.add(redirectUri))
                .build();

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);

        // Simulamos que httpClient.send() lanza IOException
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenThrow(new IOException("Simulated IO Exception"));

        // Act & Assert
        OAuth2AuthorizationCodeRequestAuthenticationException exception = assertThrows(
                OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request)
        );

        OAuth2Error error = exception.getError();
        assertEquals("invalid_client_authentication", error.getErrorCode());
        assertTrue(error.getDescription().contains("Failed to retrieve JWT from request_uri."));

        String redirectUrl = error.getUri();
        assertNotNull(redirectUrl);
        assertTrue(redirectUrl.contains(CLIENT_ERROR_ENDPOINT));
        assertTrue(redirectUrl.contains("errorCode="));
        assertTrue(redirectUrl.contains("errorMessage="));
        assertTrue(redirectUrl.contains("clientUrl="));
        assertTrue(redirectUrl.contains("originalRequestURL="));
    }

    @Test
    void convert_standardRequest_withPkce_shouldCachePkceAdditionalParameters() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        String clientId = "test-client-id";
        String state = "test-state";
        String scope = "openid learcredential";
        String redirectUri = "https://client.example.com/callback";
        String clientName = "Test Client";
        String codeChallenge = "abc123challenge";
        String codeChallengeMethod = "S256";
        String clientNonce = "test-nonce";

        when(request.getRequestURL()).thenReturn(new StringBuffer("https://client.example.com/authorize"));
        when(request.getQueryString()).thenReturn("client_id=test-client-id&scope=openid%20learcredential&state=test-state");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
        when(request.getParameter(REQUEST_URI)).thenReturn(null);
        when(request.getParameter("request")).thenReturn(null);
        when(request.getParameter(NONCE)).thenReturn(clientNonce);

        when(request.getParameter(PkceParameterNames.CODE_CHALLENGE)).thenReturn(codeChallenge);
        when(request.getParameter(PkceParameterNames.CODE_CHALLENGE_METHOD)).thenReturn(codeChallengeMethod);

        RegisteredClient registeredClient = RegisteredClient.withId("1234")
                .clientId(clientId)
                .clientName(clientName)
                .authorizationGrantType(new AuthorizationGrantType("authorization_code"))
                .redirectUri(redirectUri)
                .build();

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
        when(backendConfig.getUrl()).thenReturn("https://auth.server.com");

        ECKey ecKey = mock(ECKey.class);
        when(cryptoComponent.getECKey()).thenReturn(ecKey);
        when(ecKey.getKeyID()).thenReturn("key-id");

        OAuth2AuthorizationCodeRequestAuthenticationException ex = assertThrows(
                OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request)
        );
        assertEquals("required_external_user_authentication", ex.getError().getErrorCode());

        ArgumentCaptor<OAuth2AuthorizationRequest> captor = ArgumentCaptor.forClass(OAuth2AuthorizationRequest.class);
        verify(cacheStoreForOAuth2AuthorizationRequest).add(eq(state), captor.capture());

        OAuth2AuthorizationRequest cached = captor.getValue();
        Map<String, Object> addl = cached.getAdditionalParameters();

        assertEquals(codeChallenge, addl.get(PkceParameterNames.CODE_CHALLENGE));
        assertEquals(codeChallengeMethod, addl.get(PkceParameterNames.CODE_CHALLENGE_METHOD));
    }

    @Test
    void convert_standardRequest_withoutPkce_shouldNotCachePkceAdditionalParameters() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        String clientId = "test-client-id";
        String state = "test-state";
        String scope = "openid learcredential";
        String redirectUri = "https://client.example.com/callback";
        String clientName = "Test Client";
        String clientNonce = "test-nonce";

        when(request.getRequestURL()).thenReturn(new StringBuffer("https://client.example.com/authorize"));
        when(request.getQueryString()).thenReturn("client_id=test-client-id&scope=openid%20learcredential&state=test-state");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn(state);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);
        when(request.getParameter(REQUEST_URI)).thenReturn(null);
        when(request.getParameter("request")).thenReturn(null);
        when(request.getParameter(NONCE)).thenReturn(clientNonce);

        when(request.getParameter(PkceParameterNames.CODE_CHALLENGE)).thenReturn(null);
        when(request.getParameter(PkceParameterNames.CODE_CHALLENGE_METHOD)).thenReturn(null);

        RegisteredClient registeredClient = RegisteredClient.withId("1234")
                .clientId(clientId)
                .clientName(clientName)
                .authorizationGrantType(new AuthorizationGrantType("authorization_code"))
                .redirectUri(redirectUri)
                .build();

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(registeredClient);
        when(backendConfig.getUrl()).thenReturn("https://auth.server.com");

        ECKey ecKey = mock(ECKey.class);
        when(cryptoComponent.getECKey()).thenReturn(ecKey);
        when(ecKey.getKeyID()).thenReturn("key-id");

        // Act
        OAuth2AuthorizationCodeRequestAuthenticationException ex = assertThrows(
                OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request)
        );
        assertEquals("required_external_user_authentication", ex.getError().getErrorCode());

        ArgumentCaptor<OAuth2AuthorizationRequest> captor = ArgumentCaptor.forClass(OAuth2AuthorizationRequest.class);
        verify(cacheStoreForOAuth2AuthorizationRequest).add(eq(state), captor.capture());

        OAuth2AuthorizationRequest cached = captor.getValue();
        Map<String, Object> addl = cached.getAdditionalParameters();

        assertFalse(addl.containsKey(PkceParameterNames.CODE_CHALLENGE));
        assertFalse(addl.containsKey(PkceParameterNames.CODE_CHALLENGE_METHOD));
    }


    private void stubPkceParamsNull(HttpServletRequest request) {
        when(request.getParameter(PkceParameterNames.CODE_CHALLENGE)).thenReturn(null);
        when(request.getParameter(PkceParameterNames.CODE_CHALLENGE_METHOD)).thenReturn(null);
    }


}
