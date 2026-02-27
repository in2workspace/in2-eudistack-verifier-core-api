package es.in2.vcverifier.oauth2.infrastructure.filter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.oauth2.application.workflow.TokenGenerationWorkflow;
import es.in2.vcverifier.oauth2.domain.model.RefreshTokenDataCache;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static es.in2.vcverifier.shared.domain.util.Constants.*;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final RegisteredClientRepository registeredClientRepository;
    private final BackendConfig backendConfig;
    private final ObjectMapper objectMapper;
    private final CacheStore<RefreshTokenDataCache> cacheStoreForRefreshTokenData;
    private final OAuth2AuthorizationService oAuth2AuthorizationService;
    private final TokenGenerationWorkflow tokenGenerationWorkflow;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof OAuth2AuthorizationGrantAuthenticationToken oAuth2AuthorizationGrantAuthenticationToken) {
            log.debug("Authorization token received: {}", oAuth2AuthorizationGrantAuthenticationToken);
            return handleGrant(oAuth2AuthorizationGrantAuthenticationToken);
        }
        log.error("Unsupported grant type: {}", authentication.getClass().getName());
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE);
    }

    private Authentication handleGrant(OAuth2AuthorizationGrantAuthenticationToken authentication) {
        log.info("Processing authorization grant");

        String clientId = getClientId(authentication);
        RegisteredClient registeredClient = getRegisteredClient(clientId);

        if (authentication instanceof OAuth2AuthorizationCodeAuthenticationToken authCodeToken) {
            if (isPublicPkceClient(registeredClient)) {
                validateAuthorizationCodePkce(authCodeToken, clientId);
            } else {
                log.debug("Omitting redirect+PKCE validation for confidential client '{}'", clientId);
            }
        }

        JsonNode credentialJson = getJsonCredential(authentication);
        boolean isM2M = authentication instanceof OAuth2ClientCredentialsAuthenticationToken;

        // Resolve audience
        String audience;
        if (isM2M) {
            audience = backendConfig.getUrl();
        } else {
            Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
            if (additionalParameters.containsKey(OAuth2ParameterNames.AUDIENCE)) {
                audience = additionalParameters.get(OAuth2ParameterNames.AUDIENCE).toString();
            } else {
                // Fallback: check credential type via workflow
                String credType = tokenGenerationWorkflow.extractCredentialType(credentialJson);
                if ("LEARCredentialMachine".equals(credType)) {
                    audience = backendConfig.getUrl();
                } else {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
                }
            }
        }

        // Delegate token generation to the workflow
        TokenGenerationWorkflow.Result tokenResult = tokenGenerationWorkflow.execute(
                credentialJson, audience, authentication.getAdditionalParameters(), !isM2M);

        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                tokenResult.accessTokenJwt(),
                tokenResult.issueTime(),
                tokenResult.expirationTime()
        );

        OAuth2RefreshToken oAuth2RefreshToken;
        Map<String, Object> additionalParameters;

        if (isM2M) {
            oAuth2RefreshToken = null;
            additionalParameters = Map.of();
        } else {
            additionalParameters = Map.of("id_token", tokenResult.idTokenJwt());
            oAuth2RefreshToken = getOAuth2RefreshToken(authentication, tokenResult.issueTime(), clientId, credentialJson, registeredClient);
        }

        log.info("Authorization grant successfully processed");

        if (authentication instanceof OAuth2AuthorizationCodeAuthenticationToken authCodeToken) {
            OAuth2Authorization authToRemove = oAuth2AuthorizationService.findByToken(
                    authCodeToken.getCode(), new OAuth2TokenType(OAuth2ParameterNames.CODE));
            if (authToRemove != null) {
                oAuth2AuthorizationService.remove(authToRemove);
            }
        }

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, authentication, oAuth2AccessToken, oAuth2RefreshToken, additionalParameters);
    }

    // --- Helper methods ---

    private boolean isPublicPkceClient(RegisteredClient rc) {
        if (rc == null) return false;
        boolean isPublic = rc.getClientAuthenticationMethods().size() == 1
                && rc.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE);
        boolean requirePkce = rc.getClientSettings() != null && rc.getClientSettings().isRequireProofKey();
        return isPublic && requirePkce;
    }

    private void validateAuthorizationCodePkce(OAuth2AuthorizationCodeAuthenticationToken authCodeToken, String requestedClientId) {
        final String code = authCodeToken.getCode();

        OAuth2Authorization authorization = oAuth2AuthorizationService.findByToken(code, new OAuth2TokenType(OAuth2ParameterNames.CODE));
        if (authorization == null) invalidGrant();

        String storedClientId = authorization.getAttribute(OAuth2ParameterNames.CLIENT_ID);
        if (!Objects.equals(storedClientId, requestedClientId)) invalidGrant();

        String storedChallenge = authorization.getAttribute(PkceParameterNames.CODE_CHALLENGE);
        String storedMethod = authorization.getAttribute(PkceParameterNames.CODE_CHALLENGE_METHOD);

        boolean requirePkce = Optional.ofNullable(registeredClientRepository.findByClientId(storedClientId))
                .map(RegisteredClient::getClientSettings)
                .map(cs -> cs.isRequireProofKey())
                .orElse(false);

        if (!org.springframework.util.StringUtils.hasText(storedChallenge)) {
            if (requirePkce) invalidGrant();
            return;
        }

        String codeVerifier = (String) authCodeToken.getAdditionalParameters().get(PkceParameterNames.CODE_VERIFIER);
        if (!org.springframework.util.StringUtils.hasText(codeVerifier)) invalidGrant();

        String method = (storedMethod == null ? "S256" : storedMethod).toUpperCase(Locale.ROOT);
        switch (method) {
            case "S256" -> {
                if (!s256(codeVerifier).equals(storedChallenge)) invalidGrant();
            }
            case "PLAIN" -> {
                if (!codeVerifier.equals(storedChallenge)) invalidGrant();
            }
            default -> invalidGrant();
        }
    }

    private static void invalidGrant() {
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
    }

    private static String s256(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
    }

    private OAuth2RefreshToken getOAuth2RefreshToken(OAuth2AuthorizationGrantAuthenticationToken authentication,
                                                      Instant issueTime, String clientId,
                                                      JsonNode credentialJson, RegisteredClient registeredClient) {
        OAuth2RefreshToken oAuth2RefreshToken = generateRefreshToken(issueTime);

        RefreshTokenDataCache refreshTokenDataCache = RefreshTokenDataCache.builder()
                .refreshToken(oAuth2RefreshToken)
                .clientId(clientId)
                .verifiableCredential(credentialJson)
                .build();

        cacheStoreForRefreshTokenData.add(oAuth2RefreshToken.getTokenValue(), refreshTokenDataCache);

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(registeredClient.getId())
                .principalName(registeredClient.getClientId())
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .token(oAuth2RefreshToken)
                .attribute(Principal.class.getName(), authentication.getPrincipal())
                .build();
        oAuth2AuthorizationService.save(authorization);
        return oAuth2RefreshToken;
    }

    private String getClientId(OAuth2AuthorizationGrantAuthenticationToken authentication) {
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
        if (additionalParameters != null && additionalParameters.containsKey(OAuth2ParameterNames.CLIENT_ID)) {
            return additionalParameters.get(OAuth2ParameterNames.CLIENT_ID).toString();
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private RegisteredClient getRegisteredClient(String clientId) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }
        return registeredClient;
    }

    private JsonNode getJsonCredential(OAuth2AuthorizationGrantAuthenticationToken authentication) {
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
        if (!additionalParameters.containsKey("vc")) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        return objectMapper.convertValue(additionalParameters.get("vc"), JsonNode.class);
    }

    private OAuth2RefreshToken generateRefreshToken(Instant issueTime) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] refreshTokenBytes = new byte[32];
        secureRandom.nextBytes(refreshTokenBytes);
        String refreshTokenValue = Base64.getUrlEncoder().withoutPadding().encodeToString(refreshTokenBytes);
        Instant refreshTokenExpirationTime = issueTime.plus(
                Long.parseLong(ACCESS_TOKEN_EXPIRATION_TIME),
                ChronoUnit.valueOf(ACCESS_TOKEN_EXPIRATION_CHRONO_UNIT)
        );
        return new OAuth2RefreshToken(refreshTokenValue, issueTime, refreshTokenExpirationTime);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication)
                || OAuth2ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication)
                || OAuth2RefreshTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
