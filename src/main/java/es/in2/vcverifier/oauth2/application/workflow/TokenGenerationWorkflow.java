package es.in2.vcverifier.oauth2.application.workflow;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.domain.exception.JsonConversionException;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;
import es.in2.vcverifier.verifier.domain.service.ClaimsExtractor;
import es.in2.vcverifier.shared.crypto.JWTService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static es.in2.vcverifier.shared.domain.util.Constants.*;
import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;

/**
 * Application workflow that generates access tokens and ID tokens from a validated credential.
 * Extracts the credential type, delegates to the appropriate ClaimsExtractor SPI,
 * resolves the subject DID, and builds the JWT tokens.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenGenerationWorkflow {

    private final JWTService jwtService;
    private final BackendConfig backendConfig;
    private final ObjectMapper objectMapper;
    private final List<ClaimsExtractor> claimsExtractors;

    public record Result(
            String accessTokenJwt,
            Instant issueTime,
            Instant expirationTime,
            String idTokenJwt,
            String scope,
            String subject
    ) {}

    /**
     * Generates an access token (and optionally an ID token) from a validated credential.
     *
     * @param credentialJson       the credential as a JsonNode
     * @param audience             the audience for the tokens
     * @param additionalParameters map containing optional SCOPE, NONCE, etc.
     * @param generateIdToken      true to generate an ID token (for authorization_code and refresh_token grants)
     * @return a Result with the JWT strings and metadata
     */
    public Result execute(JsonNode credentialJson, String audience, Map<String, Object> additionalParameters, boolean generateIdToken) {
        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(
                Long.parseLong(ACCESS_TOKEN_EXPIRATION_TIME),
                ChronoUnit.valueOf(ACCESS_TOKEN_EXPIRATION_CHRONO_UNIT)
        );

        String credentialType = extractCredentialType(credentialJson);
        ExtractedClaims extractedClaims = extractClaims(credentialType, credentialJson);
        String subject = resolveSubjectDid(extractedClaims, credentialJson);

        String accessTokenJwt = buildAccessToken(credentialJson, extractedClaims, issueTime, expirationTime, subject, audience);

        String idTokenJwt = null;
        if (generateIdToken) {
            idTokenJwt = buildIdToken(credentialJson, extractedClaims, subject, audience, additionalParameters);
        }

        return new Result(accessTokenJwt, issueTime, expirationTime, idTokenJwt, extractedClaims.scope(), subject);
    }

    public String extractCredentialType(JsonNode credentialJson) {
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

    public String resolveSubjectDid(ExtractedClaims extractedClaims, JsonNode credentialJson) {
        // Priority 1: from ClaimsExtractor
        if (extractedClaims.subjectDid() != null && !extractedClaims.subjectDid().isBlank()) {
            log.info("Subject DID resolved via ClaimsExtractor");
            return extractedClaims.subjectDid();
        }
        // Priority 2: credentialSubject.id from JSON
        String csId = credentialJson.at("/credentialSubject/id").asText(null);
        if (csId != null && !csId.isBlank()) {
            log.info("Subject DID resolved via credentialSubject.id JSON path");
            return csId;
        }
        // Priority 3: mandatee.id from JSON (legacy)
        String mandateeId = credentialJson.at("/credentialSubject/mandate/mandatee/id").asText(null);
        if (mandateeId != null && !mandateeId.isBlank()) {
            log.info("Subject DID resolved via mandatee.id JSON path");
            return mandateeId;
        }
        log.error("[GRANT] Cannot resolve subject DID");
        throw new IllegalStateException("Missing cryptographic binding DID in credential");
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

    private String buildAccessToken(JsonNode credentialJson, ExtractedClaims extractedClaims,
                                     Instant issueTime, Instant expirationTime,
                                     String subject, String audience) {
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

    private String buildIdToken(JsonNode credentialJson, ExtractedClaims extractedClaims,
                                 String subject, String audience, Map<String, Object> additionalParameters) {
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

        if (additionalParameters.containsKey(OAuth2ParameterNames.SCOPE)) {
            extractedClaims.idTokenClaims().forEach(idTokenClaimsBuilder::claim);
        }

        if (additionalParameters.containsKey(NONCE)) {
            idTokenClaimsBuilder.claim(NONCE, additionalParameters.get(NONCE));
        }

        JWTClaimsSet idTokenClaims = idTokenClaimsBuilder.build();
        return jwtService.generateJWT(idTokenClaims.toString());
    }
}
