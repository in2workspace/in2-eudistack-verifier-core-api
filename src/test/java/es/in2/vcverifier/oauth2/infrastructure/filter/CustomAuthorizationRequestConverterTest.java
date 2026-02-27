package es.in2.vcverifier.oauth2.infrastructure.filter;

import es.in2.vcverifier.oauth2.infrastructure.filter.CustomAuthorizationRequestConverter;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.config.FrontendConfig;
import es.in2.vcverifier.shared.crypto.DIDService;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.verifier.application.workflow.AuthorizationRequestBuildWorkflow;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
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

import static es.in2.vcverifier.shared.domain.util.Constants.REQUEST_URI;
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
    private CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;

    @Mock
    private BackendConfig backendConfig;

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @Mock
    private HttpClient httpClient;

    @Mock
    private AuthorizationRequestBuildWorkflow authorizationRequestBuildWorkflow;

    @Mock
    private FrontendConfig frontendConfig;

    private boolean isNonceRequiredOnFapiProfile = true;

    private CustomAuthorizationRequestConverter converter;

    @BeforeEach
    void setUp() {
        lenient().when(frontendConfig.getPortalUrl()).thenReturn("http://localhost:4200");
        converter = new CustomAuthorizationRequestConverter(
                didService,
                jwtService,
                cacheStoreForOAuth2AuthorizationRequest,
                backendConfig,
                registeredClientRepository,
                isNonceRequiredOnFapiProfile,
                httpClient,
                authorizationRequestBuildWorkflow,
                frontendConfig
        );
    }

    @Test
    void convert_validStandardRequest_shouldThrowRedirectionException() {
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

        // Mock the workflow to return a result
        AuthorizationRequestBuildWorkflow.Result workflowResult = new AuthorizationRequestBuildWorkflow.Result(
                "signed-jwt", "openid4vp://?client_id=key-id&request_uri=https%3A%2F%2Fauth.server.com", "nonce-123", clientName);
        when(authorizationRequestBuildWorkflow.execute(clientName, scope, state)).thenReturn(workflowResult);

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
    }

    @Test
    void convert_fapiRequestWithInvalidRedirectUri_shouldThrowInvalidClientAuthenticationException() {
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

        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        when(signedJWT.getPayload()).thenReturn(payload);
        when(jwtService.parseJWT(jwt)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.REDIRECT_URI)).thenReturn(jwtRedirectUri);

        OAuth2AuthorizationCodeRequestAuthenticationException exception = assertThrows(
                OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request)
        );

        OAuth2Error error = exception.getError();
        assertEquals("invalid_client_authentication", error.getErrorCode());
        assertTrue(error.getDescription().contains("The redirect_uri does not match"));
    }

    @Test
    void convert_fapiRequestWithRequestUri_shouldProcessSuccessfully() throws Exception {
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

        HttpResponse<String> mockHttpResponse = mock(HttpResponse.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(200);
        when(mockHttpResponse.body()).thenReturn(jwt);

        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        when(signedJWT.getPayload()).thenReturn(payload);
        when(jwtService.parseJWT(jwt)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.SCOPE)).thenReturn(scope);
        when(jwtService.getClaimFromPayload(payload, OAuth2ParameterNames.REDIRECT_URI)).thenReturn(redirectUri);

        PublicKey publicKey = mock(PublicKey.class);
        when(didService.getPublicKeyFromDid(clientId)).thenReturn(publicKey);
        when(signedJWT.serialize()).thenReturn("serialized-jwt");
        doNothing().when(jwtService).verifyJWTWithECKey(anyString(), eq(publicKey));

        when(backendConfig.getUrl()).thenReturn("https://auth.server.com");

        // Mock the workflow
        AuthorizationRequestBuildWorkflow.Result workflowResult = new AuthorizationRequestBuildWorkflow.Result(
                "signed-auth-jwt", "openid4vp://...", "nonce-456", clientName);
        when(authorizationRequestBuildWorkflow.execute(clientName, scope, state)).thenReturn(workflowResult);

        OAuth2AuthorizationCodeRequestAuthenticationException exception = assertThrows(
                OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request)
        );

        OAuth2Error error = exception.getError();
        assertEquals("required_external_user_authentication", error.getErrorCode());

        verify(cacheStoreForOAuth2AuthorizationRequest).add(eq(state), any(OAuth2AuthorizationRequest.class));
    }

    @Test
    void convert_standardRequest_missingRedirectUri_shouldThrowException() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        String clientId = "test-client-id";

        when(request.getRequestURL()).thenReturn(new StringBuffer("https://client.example.com/authorize"));
        when(request.getQueryString()).thenReturn("client_id=test-client-id&scope=learcredential&state=test-state");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(clientId);
        when(request.getParameter(REQUEST_URI)).thenReturn(null);

        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> converter.convert(request)
        );

        assertEquals(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, exception.getError().getErrorCode());
    }

    @Test
    void convert_standardRequest_unsupportedScope_shouldThrowInvalidClientAuthenticationException() {
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

        // The workflow will throw InvalidScopeException for unsupported scope
        when(authorizationRequestBuildWorkflow.execute(clientName, scope, state))
                .thenThrow(new es.in2.vcverifier.verifier.domain.exception.InvalidScopeException(
                        "The requested scope does not contain 'learcredential'."));

        // The exception from the workflow propagates - it won't be an OAuth2AuthorizationCodeRequestAuthenticationException anymore
        assertThrows(es.in2.vcverifier.verifier.domain.exception.InvalidScopeException.class,
                () -> converter.convert(request));
    }

    @Test
    void convert_requestUriResponseNot200_shouldThrowInvalidClientAuthenticationException() throws Exception {
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

        HttpResponse<String> mockHttpResponse = mock(HttpResponse.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(mockHttpResponse);

        OAuth2AuthorizationCodeRequestAuthenticationException exception = assertThrows(
                OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request)
        );

        OAuth2Error error = exception.getError();
        assertEquals("invalid_client_authentication", error.getErrorCode());
        assertTrue(error.getDescription().contains("Failed to retrieve JWT from request_uri: Invalid response."));
    }

    @Test
    void convert_requestUriThrowsIOException_shouldThrowInvalidClientAuthenticationException() throws Exception {
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
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenThrow(new IOException("Simulated IO Exception"));

        OAuth2AuthorizationCodeRequestAuthenticationException exception = assertThrows(
                OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request)
        );

        OAuth2Error error = exception.getError();
        assertEquals("invalid_client_authentication", error.getErrorCode());
        assertTrue(error.getDescription().contains("Failed to retrieve JWT from request_uri."));
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

        AuthorizationRequestBuildWorkflow.Result workflowResult = new AuthorizationRequestBuildWorkflow.Result(
                "signed-jwt", "openid4vp://...", "nonce-789", clientName);
        when(authorizationRequestBuildWorkflow.execute(clientName, scope, state)).thenReturn(workflowResult);

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

        AuthorizationRequestBuildWorkflow.Result workflowResult = new AuthorizationRequestBuildWorkflow.Result(
                "signed-jwt", "openid4vp://...", "nonce-000", clientName);
        when(authorizationRequestBuildWorkflow.execute(clientName, scope, state)).thenReturn(workflowResult);

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
