package es.in2.vcverifier.oauth2.infrastructure.filter;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.oauth2.application.workflow.ClientCredentialsValidationWorkflow;
import es.in2.vcverifier.oauth2.domain.exception.UnsupportedGrantTypeException;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationCodeData;
import es.in2.vcverifier.oauth2.domain.model.RefreshTokenDataCache;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;

@Slf4j
@RequiredArgsConstructor
public class CustomTokenRequestConverter implements AuthenticationConverter {

    private final ClientCredentialsValidationWorkflow clientCredentialsValidationWorkflow;
    private final CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;
    private final CacheStore<RefreshTokenDataCache> refreshTokenDataCacheCacheStore;

    @Override
    public Authentication convert(HttpServletRequest request) {
        log.info("CustomTokenRequestConverter --> convert -- INIT");
        MultiValueMap<String, String> parameters = getParameters(request);
        String grantType = parameters.getFirst(OAuth2ParameterNames.GRANT_TYPE);
        if (grantType == null) {
            throw new UnsupportedGrantTypeException("The grant_type parameter is required");
        }
        return switch (grantType) {
            case "authorization_code" -> handleAuthorizationCodeGrant(parameters);
            case "client_credentials" -> handleClientCredentialsGrant(parameters);
            case "refresh_token" -> handleRefreshTokenGrant(parameters);
            default -> throw new UnsupportedGrantTypeException("Unsupported grant_type: " + grantType);
        };
    }

    private Authentication handleAuthorizationCodeGrant(MultiValueMap<String, String> parameters) {
        log.info("CustomTokenRequestConverter --> handleAuthorizationCodeGrant -- INIT");

        String code = parameters.getFirst(OAuth2ParameterNames.CODE);
        String state = parameters.getFirst(OAuth2ParameterNames.STATE);
        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        String redirectUri = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
        String codeVerifier = parameters.getFirst(PkceParameterNames.CODE_VERIFIER);

        String codePrefix = code == null ? "null" : code.substring(0, Math.min(10, code.length()));
        log.info("[AUTH_CODE] codePrefix={}, clientId={}, redirectUriPresent={}, statePresent={}, pkcePresent={}",
                codePrefix, clientId,
                redirectUri != null && !redirectUri.isBlank(),
                state != null && !state.isBlank(),
                codeVerifier != null && !codeVerifier.isBlank());

        AuthorizationCodeData authorizationCodeData = cacheStoreForAuthorizationCodeData.get(code);
        if (authorizationCodeData == null) {
            log.error("[AUTH_CODE] AuthorizationCodeData NOT FOUND for codePrefix={}", codePrefix);
            throw new IllegalArgumentException("Invalid or expired authorization code");
        }

        log.info("[AUTH_CODE] Stored data: statePresent={}, noncePresent={}, scopes={}",
                authorizationCodeData.state() != null && !authorizationCodeData.state().isBlank(),
                authorizationCodeData.clientNonce() != null && !authorizationCodeData.clientNonce().isBlank(),
                authorizationCodeData.requestedScopes());

        if (state != null && !state.isBlank() && (!authorizationCodeData.state().equals(state))) {
            log.error("State mismatch. Expected: {}, Actual: {}", authorizationCodeData.state(), state);
            throw new IllegalArgumentException("Invalid state parameter");
        }

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
        additionalParameters.put("vc", authorizationCodeData.verifiableCredential());
        additionalParameters.put(OAuth2ParameterNames.SCOPE, String.join(" ", authorizationCodeData.requestedScopes()));
        additionalParameters.put(OAuth2ParameterNames.AUDIENCE, clientId);

        String nonce = authorizationCodeData.clientNonce();
        if (nonce != null && !nonce.isBlank()) {
            additionalParameters.put(NONCE, nonce);
        }
        if (codeVerifier != null && !codeVerifier.isBlank()) {
            additionalParameters.put(PkceParameterNames.CODE_VERIFIER, codeVerifier);
        }

        log.info("Authorization code grant successfully handled");
        return new OAuth2AuthorizationCodeAuthenticationToken(code, clientPrincipal, redirectUri, additionalParameters);
    }

    private Authentication handleClientCredentialsGrant(MultiValueMap<String, String> parameters) {
        log.info("CustomTokenRequestConverter --> handleClientCredentialsGrant -- INIT");
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        String clientAssertion = parameters.getFirst(OAuth2ParameterNames.CLIENT_ASSERTION);

        // Delegate full M2M validation to the workflow
        JsonNode vc = clientCredentialsValidationWorkflow.execute(clientId, clientAssertion);

        log.info("VP Token validated successfully");
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
        additionalParameters.put("vc", vc);
        return new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal, null, additionalParameters);
    }

    private Authentication handleRefreshTokenGrant(MultiValueMap<String, String> parameters) {
        log.info("CustomTokenRequestConverter --> handleRefreshTokenGrant -- INIT");

        String refreshTokenValue = parameters.getFirst(OAuth2ParameterNames.REFRESH_TOKEN);
        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);

        RefreshTokenDataCache refreshTokenDataCache = refreshTokenDataCacheCacheStore.get(refreshTokenValue);
        if (refreshTokenDataCache == null) {
            log.error("Refresh token not found or expired");
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
        additionalParameters.put("vc", refreshTokenDataCache.verifiableCredential());
        additionalParameters.put(OAuth2ParameterNames.AUDIENCE, clientId);
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        log.info("Refresh token grant successfully handled");
        return new OAuth2RefreshTokenAuthenticationToken(refreshTokenValue, clientPrincipal, null, additionalParameters);
    }

    private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            for (String value : values) {
                parameters.add(key, value);
            }
        });
        return parameters;
    }
}
