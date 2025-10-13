package es.in2.vcverifier.security.filters;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.component.CryptoComponent;
import es.in2.vcverifier.config.BackendConfig;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.model.AuthorizationContext;
import es.in2.vcverifier.model.AuthorizationRequestJWT;
import es.in2.vcverifier.service.DIDService;
import es.in2.vcverifier.service.JWTService;
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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static es.in2.vcverifier.util.Constants.*;
import static org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames.NONCE;
import static es.in2.vcverifier.util.Constants.LOGIN_TIMEOUT;
import static es.in2.vcverifier.util.Constants.EXPIRATION;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthorizationRequestConverter implements AuthenticationConverter {

    private final DIDService didService;
    private final JWTService jwtService;
    private final CryptoComponent cryptoComponent;
    private final CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;
    private final CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    private final BackendConfig backendConfig;
    private final RegisteredClientRepository registeredClientRepository;
    private final boolean isNonceRequiredOnFapiProfile;
    private final CacheStore<String> cacheForNonceByState;

    /**
     * The Authorization Request MUST be signed by the Client, and MUST use the request_uri parameter which enables
     * the request to be passed by reference, as described in section 6.2 of the OpenID Connect spec.
     */
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

        System.out.println("XIVATO 1: "+ authorizationContext);

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

    /**
     * Handles FAPI authorization requests with a signed JWT object.
     */
    private Authentication handleFAPIRequest(AuthorizationContext authorizationContext,
                                             HttpServletRequest request,
                                             RegisteredClient registeredClient) {
        String jwt = retrieveJwtFromRequestUriOrRequest(
                authorizationContext.requestUri(),
                request,
                registeredClient,
                authorizationContext.originalRequestURL()
        );

        // Parse the JWT using JWTService
        SignedJWT signedJwt = jwtService.parseJWT(jwt);

        // Validate OAuth 2.0 parameters against JWT claims
        validateOAuth2Parameters(
                registeredClient,
                authorizationContext.scope(),
                signedJwt,
                authorizationContext.originalRequestURL()
        );

        // Validate redirect_uri with the client repository
        validateRedirectUri(
                registeredClient,
                authorizationContext.redirectUri(),
                signedJwt,
                authorizationContext.originalRequestURL()
        );

        // <-- change: validate nonce ONLY if FAPI requires it
        if (isNonceRequiredOnFapiProfile) {
            validateNonceRequired(
                    authorizationContext.clientNonce(),
                    registeredClient,
                    authorizationContext.originalRequestURL()
            );
        }

        // Process the authorization flow
        return processAuthorizationFlow(authorizationContext, signedJwt, registeredClient);
    }

    /**
     * Handles OIDC standard requests without a signed JWT object.
     * The nonce is always optional in this scenario.
     */
    private Authentication handleOIDCStandardRequest(AuthorizationContext authorizationContext,
                                                     RegisteredClient registeredClient) {
        // Validate redirect_uri for non-signed requests
        validateRedirectUri(
                registeredClient,
                authorizationContext.redirectUri(),
                null,
                authorizationContext.originalRequestURL()
        );

        // <-- change: do NOT force nonce validation; it's optional for OIDC standard requests

        // Cache the OAuth2 authorization request
        cacheAuthorizationRequest(
                authorizationContext,
                registeredClient.getClientId(),
                authorizationContext.redirectUri()
        );

        String nonce = generateNonce();

        // Build the JWT for the Authorization Request
        String signedAuthRequest = jwtService.generateJWTwithOI4VPType(
                buildAuthorizationRequestJwtPayload(
                        registeredClient,
                        authorizationContext.scope(),
                        authorizationContext.state(),
                        authorizationContext.originalRequestURL()
                )
        );

        return getAuthentication(authorizationContext.state(), signedAuthRequest, nonce, registeredClient);
    }

    /**
     * Throws an exception with the appropriate error message and URL.
     */
    private void throwInvalidClientAuthenticationException(String errorMessage,
                                                           String clientName,
                                                           String errorCode,
                                                           String originalRequestURL) {
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

    /**
     * Retrieves the JWT from either the request_uri parameter (via HTTP GET) or directly from the request parameter "request".
     */
    private String retrieveJwtFromRequestUriOrRequest(String requestUri,
                                                      HttpServletRequest request,
                                                      RegisteredClient registeredClient,
                                                      String originalRequestURL) {
        if (requestUri != null) {
            try {
                log.info("Retrieving JWT from request_uri: {}", requestUri);
                HttpClient client = HttpClient.newHttpClient();
                HttpRequest httpRequest = HttpRequest.newBuilder()
                        .uri(URI.create(requestUri))
                        .GET()
                        .build();
                HttpResponse<String> httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());

                if (httpResponse.statusCode() != 200 || StringUtils.isBlank(httpResponse.body())) {
                    String errorCode = generateNonce();
                    String errorMessage = "Failed to retrieve JWT from request_uri: Invalid response.";
                    log.error(LOG_ERROR_FORMAT, errorCode, errorMessage);
                    throwInvalidClientAuthenticationException(
                            errorMessage,
                            registeredClient.getClientName(),
                            errorCode,
                            originalRequestURL
                    );
                }

                log.debug("JWT successfully retrieved from request_uri.");
                return httpResponse.body();
            } catch (IOException | InterruptedException e) {
                String errorCode = generateNonce();
                String errorMessage = "Failed to retrieve JWT from request_uri.";
                log.error(LOG_ERROR_FORMAT, errorCode, errorMessage, e);
                // Restore interrupt status if thread was interrupted
                Thread.currentThread().interrupt();
                throwInvalidClientAuthenticationException(
                        errorMessage,
                        registeredClient.getClientName(),
                        errorCode,
                        originalRequestURL
                );
            }
        }
        return request.getParameter("request");
    }

    /**
     * Validates OAuth2 parameters against the JWT payload.
     */
    private void validateOAuth2Parameters(RegisteredClient registeredClient,
                                          String scope,
                                          SignedJWT signedJwt,
                                          String originalRequestURL) {
        String clientId = registeredClient.getClientId();
        Payload payload = signedJwt.getPayload();
        String jwtClientId = jwtService.getClaimFromPayload(payload, CLIENT_ID);
        String jwtScope = jwtService.getClaimFromPayload(payload, SCOPE);

        if (!clientId.equals(jwtClientId) || !scope.equals(jwtScope)) {
            String errorCode = generateNonce();
            String errorMessage = "The OAuth 2.0 parameters do not match the JWT claims.";
            log.error(LOG_ERROR_FORMAT, errorCode, errorMessage);
            throwInvalidClientAuthenticationException(
                    errorMessage,
                    registeredClient.getClientName(),
                    errorCode,
                    originalRequestURL
            );
        }
    }

    /**
     * Validates that the redirect_uri is registered for the given client.
     */
    private void validateRedirectUri(RegisteredClient registeredClient,
                                     String redirectUri,
                                     SignedJWT signedJwt,
                                     String originalRequestURL) {
        String jwtRedirectUri = signedJwt != null
                ? jwtService.getClaimFromPayload(signedJwt.getPayload(), OAuth2ParameterNames.REDIRECT_URI)
                : redirectUri;

        if (!registeredClient.getRedirectUris().contains(jwtRedirectUri)) {
            String errorCode = generateNonce();
            String errorMessage = "The redirect_uri does not match any of the registered client's redirect_uris.";
            log.error(LOG_ERROR_FORMAT, errorCode, errorMessage);
            throwInvalidClientAuthenticationException(
                    errorMessage,
                    registeredClient.getClientName(),
                    errorCode,
                    originalRequestURL
            );
        }
    }

    /**
     * Validates that a nonce is present (only in scenarios where it's required).
     */
    private void validateNonceRequired(String clientNonce,
                                       RegisteredClient registeredClient,
                                       String originalRequestURL) {
        if (StringUtils.isBlank(clientNonce)) {
            String errorCode = generateNonce();
            String errorMessage = "The 'nonce' parameter is required but is missing.";
            log.error(LOG_ERROR_FORMAT, errorCode, errorMessage);
            throwInvalidClientAuthenticationException(
                    errorMessage,
                    registeredClient.getClientName(),
                    errorCode,
                    originalRequestURL
            );
        }
    }

    /**
     * Processes the authorization flow after all necessary validations have passed.
     */
    private Authentication processAuthorizationFlow(AuthorizationContext authorizationContext,
                                                    SignedJWT signedJwt,
                                                    RegisteredClient registeredClient) {
        PublicKey publicKey = didService.getPublicKeyFromDid(registeredClient.getClientId());
        jwtService.verifyJWTWithECKey(signedJwt.serialize(), publicKey);

        String signedAuthRequest = jwtService.generateJWTwithOI4VPType(
                buildAuthorizationRequestJwtPayload(
                        registeredClient,
                        authorizationContext.scope(),
                        authorizationContext.state(),
                        authorizationContext.originalRequestURL()
                )
        );

        cacheAuthorizationRequest(
                authorizationContext,
                registeredClient.getClientId(),
                jwtService.getClaimFromPayload(signedJwt.getPayload(), OAuth2ParameterNames.REDIRECT_URI)
        );

        String nonce = generateNonce();
        return getAuthentication(authorizationContext.state(), signedAuthRequest, nonce, registeredClient);
    }

    /**
     * Creates an Authentication object (via an exception) to be handled by the framework.
     */
    private Authentication getAuthentication(String state,
                                             String signedAuthRequest,
                                             String nonce,
                                             RegisteredClient registeredClient) {
        cacheStoreForAuthorizationRequestJWT.add(
                nonce,
                AuthorizationRequestJWT.builder()
                        .authRequest(signedAuthRequest)
                        .build()
        );

        // This allows the user to return to the application if they cancel the login
        String homeUri = registeredClient.getClientName();

        String authRequest = generateOpenId4VpUrl(nonce);
        String redirectUrl = String.format(
                LOGIN_ENDPOINT + "?authRequest=%s&state=%s&homeUri=%s",
                URLEncoder.encode(authRequest, StandardCharsets.UTF_8),
                URLEncoder.encode(state, StandardCharsets.UTF_8),
                URLEncoder.encode(homeUri, StandardCharsets.UTF_8)
        );

        OAuth2Error error = new OAuth2Error(
                REQUIRED_EXTERNAL_USER_AUTHENTICATION,
                "Redirection required",
                redirectUrl
        );
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }

    /**
     * Builds the payload for the Authorization Request JWT.
     */
    private String buildAuthorizationRequestJwtPayload(RegisteredClient registeredClient,
                                                       String scope,
                                                       String state,
                                                       String originalRequestURL) {
        // TODO: Map the scope with its presentation definition if needed
        checkAuthorizationRequestScope(scope, registeredClient, originalRequestURL);
        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(10, ChronoUnit.DAYS);
        String nonce = generateNonce();

        JWTClaimsSet payload = new JWTClaimsSet.Builder()
                .issuer(cryptoComponent.getECKey().getKeyID())
                .audience(cryptoComponent.getECKey().getKeyID())
                .issueTime(Date.from(issueTime))
                .expirationTime(Date.from(expirationTime))
                .claim(OAuth2ParameterNames.CLIENT_ID, cryptoComponent.getECKey().getKeyID())
                .claim("client_id_scheme", "did:key")
                .claim(NONCE, nonce)
                .claim("response_uri", backendConfig.getUrl() + AUTHORIZATION_RESPONSE_ENDPOINT)
                .claim(OAuth2ParameterNames.SCOPE, "dome.credentials.presentation.LEARCredentialEmployee")
                .claim(OAuth2ParameterNames.STATE, state)
                .claim(OAuth2ParameterNames.RESPONSE_TYPE, "vp_token")
                .claim("response_mode", "direct_post")
                //.claim("dcql_query",buildDcqlQuery())
                .jwtID(UUID.randomUUID().toString())
                .build();

        cacheForNonceByState.add(state, nonce);

        return payload.toString();
    }

    /*private Map<String, Object> buildDcqlQuery() {
        return Collections.singletonMap(
                "credentials",
                List.of(Map.of("id", "LEARCredentialEmployee", "format", "jwt_vc_json"))
        );
    }*/

    /**
     * Checks that the scope contains the required 'learcredential' string.
     */
    private void checkAuthorizationRequestScope(String scope,
                                                RegisteredClient registeredClient,
                                                String originalRequestURL) {
        if (!scope.contains("learcredential")) {
            String errorCode = generateNonce();
            String errorMessage =
                    "The requested scope does not contain 'learcredential'. Only this scope and 'email', 'profile' are supported.";
            log.error(LOG_ERROR_FORMAT, errorCode, errorMessage);
            throwInvalidClientAuthenticationException(
                    errorMessage,
                    registeredClient.getClientName(),
                    errorCode,
                    originalRequestURL
            );
        }
    }

    /**
     * Constructs the openid4vp URL to which the user will be redirected for credential presentation.
     */
    private String generateOpenId4VpUrl(String nonce) {
        String requestUri = String.format("%s/oid4vp/auth-request/%s",
                backendConfig.getUrl(),
                nonce
        );
        return String.format("openid4vp://?client_id=%s&request_uri=%s",
                URLEncoder.encode(cryptoComponent.getECKey().getKeyID(), StandardCharsets.UTF_8),
                URLEncoder.encode(requestUri, StandardCharsets.UTF_8)
        );
    }

    /**
     * Generates a random nonce.
     */
    private String generateNonce() {
        return UUID.randomUUID().toString();
    }

    /**
     * Caches the OAuth2 Authorization Request in order to retrieve it later.
     */
    private void cacheAuthorizationRequest(AuthorizationContext authorizationContext,
                                           String clientId,
                                           String redirectUri) {
        // Create the builder
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
        // If there's a valid nonce, then add it as an additional parameter
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

        System.out.println("XIVATO 2: "+ additionalParameters);

        builder.additionalParameters(additionalParameters);

        // Build the request
        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = builder.build();

        // Store the request in the cache
        cacheStoreForOAuth2AuthorizationRequest.add(authorizationContext.state(), oAuth2AuthorizationRequest);
    }


    /**
     * Gets the full request URL from the HttpServletRequest, including the query string if present.
     */
    private String getFullRequestUrl(HttpServletRequest request) {
        StringBuilder requestURL = new StringBuilder(request.getRequestURL());
        String queryString = request.getQueryString();
        if (queryString != null) {
            requestURL.append('?').append(queryString);
        }
        return requestURL.toString();
    }
}