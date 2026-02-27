package es.in2.vcverifier.oauth2.infrastructure.filter;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationContext;
import es.in2.vcverifier.shared.crypto.DIDService;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.verifier.application.workflow.AuthorizationRequestBuildWorkflow;
import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static es.in2.vcverifier.shared.domain.util.Constants.*;
import static org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames.NONCE;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthorizationRequestConverter implements AuthenticationConverter {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final DIDService didService;
    private final JWTService jwtService;
    private final CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    private final BackendConfig backendConfig;
    private final RegisteredClientRepository registeredClientRepository;
    private final boolean isNonceRequiredOnFapiProfile;
    private final HttpClient httpClient;
    private final AuthorizationRequestBuildWorkflow authorizationRequestBuildWorkflow;

    @Override
    public Authentication convert(HttpServletRequest request) {
        log.info("CustomAuthorizationRequestConverter.convert");

        String originalRequestURL = getFullRequestUrl(request);

        String requestUri = request.getParameter(REQUEST_URI);
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        String state = request.getParameter(OAuth2ParameterNames.STATE);
        String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
        String redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);
        String clientNonce = request.getParameter(NONCE);
        String codeChallenge = request.getParameter(PkceParameterNames.CODE_CHALLENGE);
        String codeChallengeMethod = request.getParameter(PkceParameterNames.CODE_CHALLENGE_METHOD);
        AuthorizationContext authorizationContext = AuthorizationContext.builder()
                .requestUri(requestUri)
                .state(state)
                .originalRequestURL(originalRequestURL)
                .redirectUri(redirectUri)
                .clientNonce(clientNonce)
                .codeChallenge(codeChallenge)
                .codeChallengeMethod(codeChallengeMethod)
                .scope(scope)
                .build();

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            log.error("Unauthorized client: Client with ID {} not found.", clientId);
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        // Case 1: Standard OIDC authorization request without a signed JWT object
        if (requestUri == null && request.getParameter("request") == null) {
            log.info("Processing an authorization request without a signed JWT object.");
            return handleOIDCStandardRequest(authorizationContext, registeredClient);
        }

        // Case 2: FAPI authorization request with a signed JWT object
        return handleFAPIRequest(authorizationContext, request, registeredClient);
    }

    private Authentication handleFAPIRequest(AuthorizationContext authorizationContext,
                                             HttpServletRequest request,
                                             RegisteredClient registeredClient) {
        String jwt = retrieveJwtFromRequestUriOrRequest(
                authorizationContext.requestUri(), request, registeredClient, authorizationContext.originalRequestURL());

        SignedJWT signedJwt = jwtService.parseJWT(jwt);

        validateOAuth2Parameters(registeredClient, authorizationContext.scope(), signedJwt, authorizationContext.originalRequestURL());
        validateRedirectUri(registeredClient, authorizationContext.redirectUri(), signedJwt, authorizationContext.originalRequestURL());

        if (isNonceRequiredOnFapiProfile) {
            validateNonceRequired(authorizationContext.clientNonce(), registeredClient, authorizationContext.originalRequestURL());
        }

        return processAuthorizationFlow(authorizationContext, signedJwt, registeredClient);
    }

    private Authentication handleOIDCStandardRequest(AuthorizationContext authorizationContext,
                                                     RegisteredClient registeredClient) {
        validateRedirectUri(registeredClient, authorizationContext.redirectUri(), null, authorizationContext.originalRequestURL());

        cacheAuthorizationRequest(authorizationContext, registeredClient.getClientId(), authorizationContext.redirectUri());

        // Delegate JWT building, signing, caching, and URL generation to the workflow
        AuthorizationRequestBuildWorkflow.Result result = authorizationRequestBuildWorkflow.execute(
                registeredClient.getClientName(), authorizationContext.scope(), authorizationContext.state());

        return throwRedirectAuthentication(authorizationContext.state(), result);
    }

    private Authentication processAuthorizationFlow(AuthorizationContext authorizationContext,
                                                    SignedJWT signedJwt,
                                                    RegisteredClient registeredClient) {
        PublicKey publicKey = didService.getPublicKeyFromDid(registeredClient.getClientId());
        jwtService.verifyJWTWithECKey(signedJwt.serialize(), publicKey);

        cacheAuthorizationRequest(
                authorizationContext,
                registeredClient.getClientId(),
                jwtService.getClaimFromPayload(signedJwt.getPayload(), OAuth2ParameterNames.REDIRECT_URI));

        // Delegate JWT building, signing, caching, and URL generation to the workflow
        AuthorizationRequestBuildWorkflow.Result result = authorizationRequestBuildWorkflow.execute(
                registeredClient.getClientName(), authorizationContext.scope(), authorizationContext.state());

        return throwRedirectAuthentication(authorizationContext.state(), result);
    }

    /**
     * Throws the redirect exception that Spring Authorization Server uses to redirect the user
     * to the login/QR page with the openid4vp URL.
     */
    private Authentication throwRedirectAuthentication(String state, AuthorizationRequestBuildWorkflow.Result result) {
        String redirectUrl = String.format(
                LOGIN_ENDPOINT + "?authRequest=%s&state=%s&homeUri=%s",
                URLEncoder.encode(result.openid4vpUrl(), StandardCharsets.UTF_8),
                URLEncoder.encode(state, StandardCharsets.UTF_8),
                URLEncoder.encode(result.homeUri(), StandardCharsets.UTF_8)
        );

        OAuth2Error error = new OAuth2Error(REQUIRED_EXTERNAL_USER_AUTHENTICATION, "Redirection required", redirectUrl);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }

    // --- Validation methods (framework-level, kept in filter) ---

    private void throwInvalidClientAuthenticationException(String errorMessage, String clientName,
                                                           String errorCode, String originalRequestURL) {
        String redirectUrl = String.format(
                CLIENT_ERROR_ENDPOINT + "?errorCode=%s&errorMessage=%s&clientUrl=%s&originalRequestURL=%s",
                URLEncoder.encode(errorCode, StandardCharsets.UTF_8),
                URLEncoder.encode(errorMessage, StandardCharsets.UTF_8),
                URLEncoder.encode(clientName, StandardCharsets.UTF_8),
                URLEncoder.encode(originalRequestURL, StandardCharsets.UTF_8)
        );
        OAuth2Error error = new OAuth2Error("invalid_client_authentication", errorMessage, redirectUrl);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }

    private String retrieveJwtFromRequestUriOrRequest(String requestUri, HttpServletRequest request,
                                                      RegisteredClient registeredClient, String originalRequestURL) {
        if (requestUri != null) {
            try {
                log.info("Retrieving JWT from request_uri: {}", requestUri);
                HttpRequest httpRequest = HttpRequest.newBuilder()
                        .uri(URI.create(requestUri)).timeout(REQUEST_TIMEOUT).GET().build();
                HttpResponse<String> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

                if (httpResponse.statusCode() != 200 || StringUtils.isBlank(httpResponse.body())) {
                    String errorCode = UUID.randomUUID().toString();
                    throwInvalidClientAuthenticationException("Failed to retrieve JWT from request_uri: Invalid response.",
                            registeredClient.getClientName(), errorCode, originalRequestURL);
                }
                return httpResponse.body();
            } catch (IOException | InterruptedException e) {
                Thread.currentThread().interrupt();
                String errorCode = UUID.randomUUID().toString();
                throwInvalidClientAuthenticationException("Failed to retrieve JWT from request_uri.",
                        registeredClient.getClientName(), errorCode, originalRequestURL);
            }
        }
        return request.getParameter("request");
    }

    private void validateOAuth2Parameters(RegisteredClient registeredClient, String scope,
                                          SignedJWT signedJwt, String originalRequestURL) {
        Payload payload = signedJwt.getPayload();
        String jwtClientId = jwtService.getClaimFromPayload(payload, CLIENT_ID);
        String jwtScope = jwtService.getClaimFromPayload(payload, SCOPE);

        if (!registeredClient.getClientId().equals(jwtClientId) || !scope.equals(jwtScope)) {
            throwInvalidClientAuthenticationException("The OAuth 2.0 parameters do not match the JWT claims.",
                    registeredClient.getClientName(), UUID.randomUUID().toString(), originalRequestURL);
        }
    }

    private void validateRedirectUri(RegisteredClient registeredClient, String redirectUri,
                                     SignedJWT signedJwt, String originalRequestURL) {
        String jwtRedirectUri = signedJwt != null
                ? jwtService.getClaimFromPayload(signedJwt.getPayload(), OAuth2ParameterNames.REDIRECT_URI)
                : redirectUri;

        if (!registeredClient.getRedirectUris().contains(jwtRedirectUri)) {
            throwInvalidClientAuthenticationException("The redirect_uri does not match any of the registered client's redirect_uris.",
                    registeredClient.getClientName(), UUID.randomUUID().toString(), originalRequestURL);
        }
    }

    private void validateNonceRequired(String clientNonce, RegisteredClient registeredClient, String originalRequestURL) {
        if (StringUtils.isBlank(clientNonce)) {
            throwInvalidClientAuthenticationException("The 'nonce' parameter is required but is missing.",
                    registeredClient.getClientName(), UUID.randomUUID().toString(), originalRequestURL);
        }
    }

    private void cacheAuthorizationRequest(AuthorizationContext authorizationContext, String clientId, String redirectUri) {
        OAuth2AuthorizationRequest.Builder builder = OAuth2AuthorizationRequest
                .authorizationCode()
                .state(authorizationContext.state())
                .clientId(clientId)
                .redirectUri(redirectUri)
                .scope(authorizationContext.scope())
                .authorizationUri(backendConfig.getUrl());

        Map<String, Object> additionalParameters = new HashMap<>();
        long timeout = Long.parseLong(LOGIN_TIMEOUT);
        additionalParameters.put(EXPIRATION, Instant.now().plusSeconds(timeout).getEpochSecond());

        String nonce = authorizationContext.clientNonce();
        if (nonce != null && !nonce.isBlank()) {
            additionalParameters.put(NONCE, nonce);
        }
        String codeChallenge = authorizationContext.codeChallenge();
        if (codeChallenge != null && !codeChallenge.isBlank()) {
            additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, codeChallenge);
        }
        String codeChallengeMethod = authorizationContext.codeChallengeMethod();
        if (codeChallengeMethod != null && !codeChallengeMethod.isBlank()) {
            additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, codeChallengeMethod);
        }

        builder.additionalParameters(additionalParameters);
        cacheStoreForOAuth2AuthorizationRequest.add(authorizationContext.state(), builder.build());
    }

    private String getFullRequestUrl(HttpServletRequest request) {
        StringBuilder requestURL = new StringBuilder(request.getRequestURL());
        String queryString = request.getQueryString();
        if (queryString != null) {
            requestURL.append('?').append(queryString);
        }
        return requestURL.toString();
    }
}
