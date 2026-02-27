package es.in2.vcverifier.security.filters;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.config.BackendConfig;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.shared.domain.exception.JsonConversionException;
import es.in2.vcverifier.oauth2.domain.model.RefreshTokenDataCache;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;
import es.in2.vcverifier.verifier.domain.service.ClaimsExtractor;
import es.in2.vcverifier.shared.crypto.JWTService;
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
import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final JWTService jwtService;
    private final RegisteredClientRepository registeredClientRepository;
    private final BackendConfig backendConfig;
    private final ObjectMapper objectMapper;
    private final CacheStore<RefreshTokenDataCache> cacheStoreForRefreshTokenData;
    private final OAuth2AuthorizationService oAuth2AuthorizationService;
    private final List<ClaimsExtractor> claimsExtractors;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof OAuth2AuthorizationGrantAuthenticationToken oAuth2AuthorizationGrantAuthenticationToken) {
            log.debug("Authorization token received: {}", oAuth2AuthorizationGrantAuthenticationToken);
            return handleGrant(oAuth2AuthorizationGrantAuthenticationToken);
        }
        log.error("Unsupported grant type: {}", authentication.getClass().getName());
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE);
    }

    private Authentication handleGrant(
            OAuth2AuthorizationGrantAuthenticationToken authentication) {
        log.info("Processing authorization grant");

        String clientId = getClientId(authentication);
        log.debug("Client ID obtained: {}", clientId);

        RegisteredClient registeredClient = getRegisteredClient(clientId);

        if (authentication instanceof OAuth2AuthorizationCodeAuthenticationToken authCodeToken) {
            if (isPublicPkceClient(registeredClient)) {
                validateAuthorizationCodePkce(authCodeToken, clientId);
            } else {
                log.debug("Omitting redirect+PKCE validation for confidential client '{}'", clientId);
            }
        }

        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(
                Long.parseLong(ACCESS_TOKEN_EXPIRATION_TIME),
                ChronoUnit.valueOf(ACCESS_TOKEN_EXPIRATION_CHRONO_UNIT)
        );

        JsonNode credentialJson = getJsonCredential(authentication);

        // Extract claims using the SPI chain (replaces all instanceof chains)
        String credentialType = extractCredentialType(credentialJson);
        ExtractedClaims extractedClaims = extractClaims(credentialType, credentialJson);

        String subject = resolveSubjectDid(extractedClaims, credentialJson);
        log.debug("Credential subject obtained: {}", subject);

        String audience = getAudience(authentication, credentialType);
        log.debug("Audience for credential: {}", audience);

        String jwtToken = generateAccessTokenWithVc(credentialJson, extractedClaims, issueTime, expirationTime, subject, audience);

        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                jwtToken,
                issueTime,
                expirationTime
        );

        OAuth2RefreshToken oAuth2RefreshToken;
        Map<String, Object> additionalParameters;

        if (authentication instanceof OAuth2ClientCredentialsAuthenticationToken) {
            oAuth2RefreshToken = null;
            additionalParameters = Map.of();
        } else {
            additionalParameters = Map.of(
                    "id_token",
                    generateIdToken(credentialJson, extractedClaims, subject, audience, authentication.getAdditionalParameters()));

            oAuth2RefreshToken = getOAuth2RefreshToken(
                    authentication,
                    issueTime,
                    clientId,
                    credentialJson,
                    registeredClient);
        }

        log.info("Authorization grant successfully processed");

        if (authentication instanceof OAuth2AuthorizationCodeAuthenticationToken authCodeToken) {
            OAuth2Authorization authToRemove =
                    oAuth2AuthorizationService.findByToken(authCodeToken.getCode(),
                            new OAuth2TokenType(OAuth2ParameterNames.CODE));
            if (authToRemove != null) {
                oAuth2AuthorizationService.remove(authToRemove);
            }
        }
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, authentication, oAuth2AccessToken, oAuth2RefreshToken, additionalParameters);
    }

    private ExtractedClaims extractClaims(String credentialType, JsonNode credentialJson) {
        for (ClaimsExtractor extractor : claimsExtractors) {
            if (extractor.supports(credentialType)) {
                return extractor.extract(credentialJson);
            }
        }
        throw new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.INVALID_REQUEST,
                "No claims extractor found for credential type: " + credentialType,
                null));
    }

    private String extractCredentialType(JsonNode credentialJson) {
        // W3C VCDM: type array
        JsonNode typeNode = credentialJson.get("type");
        if (typeNode != null && typeNode.isArray()) {
            for (JsonNode t : typeNode) {
                String type = t.asText();
                if (!"VerifiableCredential".equals(type) && !"VerifiableAttestation".equals(type)) {
                    return type;
                }
            }
        }
        // SD-JWT VC: vct claim
        JsonNode vctNode = credentialJson.get("vct");
        if (vctNode != null && vctNode.isTextual()) {
            String vct = vctNode.asText();
            if (vct.contains("LEARCredentialEmployee") || vct.contains("lear_credential_employee")) {
                return "LEARCredentialEmployee";
            }
            if (vct.contains("LEARCredentialMachine") || vct.contains("lear_credential_machine")) {
                return "LEARCredentialMachine";
            }
            return vct;
        }
        throw new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.INVALID_REQUEST,
                "Cannot determine credential type from 'type' or 'vct' field",
                null));
    }

    private String resolveSubjectDid(ExtractedClaims extractedClaims, JsonNode credentialJson) {
        // Priority 1: from ClaimsExtractor
        if (extractedClaims.subjectDid() != null && !extractedClaims.subjectDid().isBlank()) {
            log.info("Subject DID resolved via ClaimsExtractor");
            return extractedClaims.subjectDid();
        }

        // Priority 2: credentialSubject.id from JSON (fallback)
        String csId = credentialJson.at("/credentialSubject/id").asText(null);
        if (csId != null && !csId.isBlank()) {
            log.info("Subject DID resolved via credentialSubject.id JSON path");
            return csId;
        }

        // Priority 3: mandatee.id from JSON (legacy fallback)
        String mandateeId = credentialJson.at("/credentialSubject/mandate/mandatee/id").asText(null);
        if (mandateeId != null && !mandateeId.isBlank()) {
            log.info("Subject DID resolved via mandatee.id JSON path");
            return mandateeId;
        }

        log.error("[GRANT] Cannot resolve subject DID. Paths checked: extractedClaims, credentialSubject.id, mandatee.id");
        throw new IllegalStateException("Missing cryptographic binding DID in credential");
    }

    private String getAudience(OAuth2AuthorizationGrantAuthenticationToken authentication, String credentialType) {
        if ("LEARCredentialMachine".equals(credentialType)) {
            return backendConfig.getUrl();
        }
        // For employee credentials, get audience from additional parameters
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
        if (additionalParameters.containsKey(OAuth2ParameterNames.AUDIENCE)) {
            return additionalParameters.get(OAuth2ParameterNames.AUDIENCE).toString();
        }
        log.error("Parameter 'audience' not found in additional parameters");
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private String generateAccessTokenWithVc(JsonNode credentialJson, ExtractedClaims extractedClaims, Instant issueTime, Instant expirationTime, String subject, String audience) {
        log.info("Generating access token with verifiableCredential");

        Map<String, Object> credentialData = objectMapper.convertValue(credentialJson, new TypeReference<>() {});

        JWTClaimsSet payload = new JWTClaimsSet.Builder()
                .issuer(backendConfig.getUrl())
                .audience(audience)
                .subject(subject)
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(issueTime))
                .expirationTime(Date.from(expirationTime))
                .claim(OAuth2ParameterNames.SCOPE, extractedClaims.scope())
                .claim(CLIENT_ID, backendConfig.getUrl())
                .claim("vc", credentialData)
                .build();

        return jwtService.generateJWT(payload.toString());
    }

    private String generateIdToken(JsonNode credentialJson, ExtractedClaims extractedClaims, String subject, String audience, Map<String, Object> additionalParameters) {
        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(
                Long.parseLong(ID_TOKEN_EXPIRATION_TIME),
                ChronoUnit.valueOf(ID_TOKEN_EXPIRATION_CHRONO_UNIT)
        );

        String verifiableCredentialJson;
        try {
            verifiableCredentialJson = objectMapper.writeValueAsString(credentialJson);
        } catch (Exception e) {
            throw new JsonConversionException("Error converting Verifiable Credential to JSON: " + e.getMessage());
        }

        JWTClaimsSet.Builder idTokenClaimsBuilder = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(backendConfig.getUrl())
                .audience(audience)
                .issueTime(Date.from(issueTime))
                .expirationTime(Date.from(expirationTime))
                .claim("auth_time", Date.from(issueTime))
                .claim("acr", "0")
                .claim("vc_json", verifiableCredentialJson);

        // Add ID token claims from the extractor (name, email, etc.)
        if (additionalParameters.containsKey(OAuth2ParameterNames.SCOPE)) {
            extractedClaims.idTokenClaims().forEach(idTokenClaimsBuilder::claim);
        }

        if (additionalParameters.containsKey(NONCE)) {
            idTokenClaimsBuilder.claim(NONCE, additionalParameters.get(NONCE));
        }

        JWTClaimsSet idTokenClaims = idTokenClaimsBuilder.build();
        return jwtService.generateJWT(idTokenClaims.toString());
    }

    // --- Helper methods (unchanged) ---

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
        String storedMethod    = authorization.getAttribute(PkceParameterNames.CODE_CHALLENGE_METHOD);

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
                String computed = s256(codeVerifier);
                if (!computed.equals(storedChallenge)) invalidGrant();
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

    private OAuth2RefreshToken getOAuth2RefreshToken(OAuth2AuthorizationGrantAuthenticationToken authentication, Instant issueTime, String clientId, JsonNode credentialJson, RegisteredClient registeredClient) {
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
        log.error("Client ID not found in additional parameters");
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private RegisteredClient getRegisteredClient(String clientId) {
        log.info("Looking up registered client with Client ID: {}", clientId);
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            log.error("Registered client not found for Client ID: {}", clientId);
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
