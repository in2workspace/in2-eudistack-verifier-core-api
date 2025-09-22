package es.in2.vcverifier.security.filters;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.config.BackendConfig;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.exception.JsonConversionException;
import es.in2.vcverifier.model.RefreshTokenDataCache;
import es.in2.vcverifier.model.credentials.lear.LEARCredential;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployee;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV1;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV2;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV3;
import es.in2.vcverifier.model.credentials.lear.employee.subject.CredentialSubjectV2;
import es.in2.vcverifier.model.credentials.lear.employee.subject.CredentialSubjectV3;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.MandateV2;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.MandateV3;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.mandatee.MandateeV2;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.mandatee.MandateeV3;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.mandator.MandatorV3;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.power.PowerV2;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.power.PowerV3;
import es.in2.vcverifier.model.credentials.lear.machine.LEARCredentialMachineV1;
import es.in2.vcverifier.model.enums.LEARCredentialType;
import es.in2.vcverifier.service.JWTService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.security.Principal;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static es.in2.vcverifier.util.Constants.*;
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
        log.debug("CustomAuthenticationProvider -- handleGrant -- Client ID obtained: {}", clientId);

        RegisteredClient registeredClient = getRegisteredClient(clientId);
        log.debug("CustomAuthenticationProvider -- handleGrant -- Registered client found: {}", registeredClient);

        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(
                Long.parseLong(ACCESS_TOKEN_EXPIRATION_TIME),
                ChronoUnit.valueOf(ACCESS_TOKEN_EXPIRATION_CHRONO_UNIT)
        );
        log.debug("CustomAuthenticationProvider -- handleGrant -- Issue time: {}, Expiration time: {}", issueTime, expirationTime);

        JsonNode credentialJson = getJsonCredential(authentication);
        LEARCredential credential = getVerifiableCredential(authentication, credentialJson);
        String subject = credential.mandateeId();
        log.debug("CustomAuthenticationProvider -- handleGrant -- Credential subject obtained: {}", subject);

        String audience = getAudience(authentication, credential);
        log.debug("CustomAuthenticationProvider -- handleGrant -- Audience for credential: {}", audience);

        String jwtToken = generateAccessTokenWithVc(credential, issueTime, expirationTime, subject, audience);
        log.debug("CustomAuthenticationProvider -- handleGrant -- Generated JWT token: {}", jwtToken);

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
                    generateIdToken(credential, subject, audience, authentication.getAdditionalParameters()));

            oAuth2RefreshToken = getOAuth2RefreshToken(
                    authentication,
                    issueTime,
                    clientId,
                    credentialJson,
                    registeredClient);
        }

        log.info("Authorization grant successfully processed");
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, authentication, oAuth2AccessToken, oAuth2RefreshToken, additionalParameters);
    }

    private OAuth2RefreshToken getOAuth2RefreshToken(OAuth2AuthorizationGrantAuthenticationToken authentication, Instant issueTime, String clientId, JsonNode credentialJson, RegisteredClient registeredClient) {
        OAuth2RefreshToken oAuth2RefreshToken;
        oAuth2RefreshToken = generateRefreshToken(issueTime);

        // Generate the data necessary to be able to refresh the token
        RefreshTokenDataCache refreshTokenDataCache = RefreshTokenDataCache.builder()
                .refreshToken(oAuth2RefreshToken)
                .clientId(clientId)
                .verifiableCredential(credentialJson)
                .build();

        cacheStoreForRefreshTokenData.add(oAuth2RefreshToken.getTokenValue(),refreshTokenDataCache);

        // Save the OAuth2Authorization
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
        // Extract the client ID from the additional parameters
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
        if (additionalParameters != null && additionalParameters.containsKey(OAuth2ParameterNames.CLIENT_ID)) {
            return additionalParameters.get(OAuth2ParameterNames.CLIENT_ID).toString();
        }
        log.error("CustomAuthenticationProvider -- getClientId -- Client ID not found in additional parameters");
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private RegisteredClient getRegisteredClient(String clientId) {
        log.info("Looking up registered client with Client ID: {}", clientId);
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            log.error("CustomAuthenticationProvider -- getRegisteredClient -- Registered client not found for Client ID: {}", clientId);
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

    private LEARCredential getVerifiableCredential(OAuth2AuthorizationGrantAuthenticationToken authentication, JsonNode verifiableCredential) {
        if (authentication instanceof OAuth2AuthorizationCodeAuthenticationToken ||
                authentication instanceof OAuth2RefreshTokenAuthenticationToken) {

            // Extract and validate the '@context' field from the JsonNode
            List<String> contextList = extractContextFromJson(verifiableCredential);

            if (contextList.equals(LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT)) {
                return objectMapper.convertValue(verifiableCredential, LEARCredentialEmployeeV1.class);
            } else if (contextList.equals(LEAR_CREDENTIAL_EMPLOYEE_V2_CONTEXT)) {
                LEARCredentialEmployeeV2 learCredentialEmployeeV2 = objectMapper.convertValue(verifiableCredential, LEARCredentialEmployeeV2.class);
                return normalizeLearCredentialEmployeeV2(learCredentialEmployeeV2);
            } else if(contextList.equals(LEAR_CREDENTIAL_EMPLOYEE_V3_CONTEXT)){
                return objectMapper.convertValue(verifiableCredential, LEARCredentialEmployeeV3.class);

            }
            else {
                throw new OAuth2AuthenticationException(new OAuth2Error(
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        "Unknown LEARCredentialEmployee version: " + contextList,
                        null));
            }
        } else if (authentication instanceof OAuth2ClientCredentialsAuthenticationToken) {
            return objectMapper.convertValue(verifiableCredential, LEARCredentialMachineV1.class);
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }


    private List<String> extractContextFromJson(JsonNode verifiableCredential) {
        JsonNode contextNode = verifiableCredential.get("@context");
        if (contextNode == null || !contextNode.isArray()) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    "'@context' field is missing or is not an array",
                    null));
        }

        List<String> contextList = new ArrayList<>();
        for (JsonNode node : contextNode) {
            if (!node.isTextual()) {
                throw new OAuth2AuthenticationException(new OAuth2Error(
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        "Elements of '@context' must be strings",
                        null));
            }
            contextList.add(node.asText());
        }
        return contextList;
    }

    private String getAudience(OAuth2AuthorizationGrantAuthenticationToken authentication, LEARCredential credential) {
        // Extract the audience based on the type of credential
        if (credential instanceof LEARCredentialMachineV1) {
            return backendConfig.getUrl();
        } else if (credential instanceof LEARCredentialEmployeeV1 || credential instanceof LEARCredentialEmployeeV2 || credential instanceof LEARCredentialEmployeeV3) {
            // Get the audience from the additional parameters
            Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
            if (additionalParameters.containsKey(OAuth2ParameterNames.AUDIENCE)) {
                return additionalParameters.get(OAuth2ParameterNames.AUDIENCE).toString();
            } else {
                log.error("CustomAuthenticationProvider -- getAudience -- Parameter 'audience' not found in additional parameters");
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            }
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private String generateAccessTokenWithVc(LEARCredential learCredential, Instant issueTime, Instant expirationTime, String subject, String audience) {
        log.info("Generating access token with verifiableCredential");

        // Build the JWTClaimsSet builder
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .issuer(backendConfig.getUrl())
                .audience(audience)
                .subject(subject)
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(issueTime))
                .expirationTime(Date.from(expirationTime))
                .claim(OAuth2ParameterNames.SCOPE, getScope(learCredential))
                .claim(CLIENT_ID, backendConfig.getUrl());

        List<String> credentialTypes = learCredential.type();
        if (credentialTypes.contains(LEARCredentialType.LEAR_CREDENTIAL_EMPLOYEE.getValue())) {
            List<String> context = learCredential.context();
            if (context.equals(LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT)) {
                LEARCredentialEmployeeV1 credential = objectMapper.convertValue(learCredential, LEARCredentialEmployeeV1.class);
                Map<String, Object> credentialData = objectMapper.convertValue(credential, new TypeReference<>() {});
                claimsBuilder.claim("vc", credentialData);
            } else if (context.equals(LEAR_CREDENTIAL_EMPLOYEE_V2_CONTEXT)) {
                LEARCredentialEmployeeV2 credential = objectMapper.convertValue(learCredential, LEARCredentialEmployeeV2.class);
                Map<String, Object> credentialData = objectMapper.convertValue(credential, new TypeReference<>() {});
                claimsBuilder.claim("vc", credentialData);
            } else if (context.equals(LEAR_CREDENTIAL_EMPLOYEE_V3_CONTEXT)) {
                LEARCredentialEmployeeV3 credential = objectMapper.convertValue(learCredential, LEARCredentialEmployeeV3.class);
                Map<String, Object> credentialData = objectMapper.convertValue(credential, new TypeReference<>() {});
                claimsBuilder.claim("vc", credentialData);
            } else {
                throw new InvalidCredentialTypeException("Unknown LEARCredentialEmployee version: " + context);
            }
        } else if (credentialTypes.contains(LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue())) {
            LEARCredentialMachineV1 credential = (LEARCredentialMachineV1) learCredential;
            Map<String, Object> credentialData = objectMapper.convertValue(credential, new TypeReference<>() {});
            claimsBuilder.claim("vc", credentialData);
        } else {
            throw new InvalidCredentialTypeException("Unsupported credential type: " + credentialTypes);
        }

        JWTClaimsSet payload = claimsBuilder.build();

        return jwtService.generateJWT(payload.toString());
    }


    private String generateIdToken(LEARCredential learCredential, String subject, String audience, Map<String, Object> additionalParameters) {
        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(
                Long.parseLong(ID_TOKEN_EXPIRATION_TIME),
                ChronoUnit.valueOf(ID_TOKEN_EXPIRATION_CHRONO_UNIT)
        );

        // Convert the VerifiableCredential to a JSON string
        String verifiableCredentialJson;
        try {
            verifiableCredentialJson = objectMapper.writeValueAsString(learCredential);
        } catch (JsonProcessingException e) {
            throw new JsonConversionException("Error converting Verifiable Credential to JSON: " + e.getMessage());
        }

        // Create the JWT payload (claims) for the ID token
        JWTClaimsSet.Builder idTokenClaimsBuilder = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(backendConfig.getUrl())
                .audience(audience)
                .issueTime(Date.from(issueTime))
                .expirationTime(Date.from(expirationTime))
                .claim("auth_time", Date.from(issueTime))
                .claim("acr", "0")
                // Here is used in json format string to be able to save the VC in json format as Keycloak user attribute
                .claim("vc_json", verifiableCredentialJson);

        // Add each additional claim to the ID token
        // Extract additional claims from the verifiable credential
        Map<String, Object> additionalClaims;

        if (additionalParameters.containsKey(OAuth2ParameterNames.SCOPE)) {
            additionalClaims = extractClaimsFromVerifiableCredential(learCredential);
            additionalClaims.forEach(idTokenClaimsBuilder::claim);
        }

        // This is used only in the authorization code flow
        if (additionalParameters.containsKey(NONCE)) {
            idTokenClaimsBuilder.claim(NONCE, additionalParameters.get(NONCE));
        }

        JWTClaimsSet idTokenClaims = idTokenClaimsBuilder.build();

        // Use JWTService to generate the ID Token (JWT)
        return jwtService.generateJWT(idTokenClaims.toString());
    }

    private OAuth2RefreshToken generateRefreshToken(Instant issueTime) {
        // Generate a random refresh token with at least 128 bits of entropy. Here we use 256 bits (32 bytes)
        SecureRandom secureRandom = new SecureRandom();
        byte[] refreshTokenBytes = new byte[32]; // 256 bits
        secureRandom.nextBytes(refreshTokenBytes);
        String refreshTokenValue = Base64.getUrlEncoder().withoutPadding().encodeToString(refreshTokenBytes);

        // Use the expiration time of the access token to calculate the expiration time of the refresh token
        Instant refreshTokenExpirationTime = issueTime.plus(
                Long.parseLong(ACCESS_TOKEN_EXPIRATION_TIME),
                ChronoUnit.valueOf(ACCESS_TOKEN_EXPIRATION_CHRONO_UNIT)
        );
        log.debug("CustomAuthenticationProvider -- generateRefreshToken -- Refresh Token Expiration time: {}", refreshTokenExpirationTime);

        // Create the OAuth2RefreshToken object
        return new OAuth2RefreshToken(refreshTokenValue, issueTime, refreshTokenExpirationTime);
    }


    private Map<String, Object> extractClaimsFromVerifiableCredential(LEARCredential learCredential) {
        Map<String, Object> claims = new HashMap<>();
        if (learCredential instanceof LEARCredentialEmployee learCredentialEmployee) {
                String name = learCredentialEmployee.mandateeFirstName() + " " + learCredentialEmployee.mandateeLastName();
                claims.put("name", name);
                claims.put("given_name", learCredentialEmployee.mandateeFirstName());
                claims.put("family_name", learCredentialEmployee.mandateeLastName());
                claims.put("email", learCredentialEmployee.mandateeEmail());
                claims.put("email_verified", true);
        }
        return claims;
    }


    private String getScope(LEARCredential learCredential) {
        if (learCredential instanceof LEARCredentialEmployeeV1 || learCredential instanceof LEARCredentialEmployeeV2 || learCredential instanceof LEARCredentialEmployeeV3) {
            return "openid learcredential";
        } else if (learCredential instanceof LEARCredentialMachineV1) {
            return "machine learcredential";
        } else {
            throw new InvalidCredentialTypeException("Credential Type not supported: " + learCredential.getClass().getName());
        }
    }

    /**
     * FIXME: Temporary workaround to normalize LEAR V2 credential for compatibility.
     * This function copies V2 attributes into their legacy counterparts.
     */
    private LEARCredentialEmployee normalizeLearCredentialEmployeeV2(LEARCredentialEmployeeV2 credentialV2) {
        // Cast the mandatee to MandateeV2
        MandateeV2 originalMandatee = credentialV2.credentialSubjectV2().mandate().mandatee();
        MandateeV2 normalizedMandatee = MandateeV2.builder()
                .id(originalMandatee.id())
                .email(originalMandatee.email())
                .firstName(originalMandatee.firstName())
                .lastName(originalMandatee.lastName())
                .nationality(originalMandatee.nationality())
                .firstNameV1(originalMandatee.firstName())
                .lastNameV1(originalMandatee.lastName())
                .build();

        // Normalize each PowerV2: duplicate values into tmf_* fields for compatibility
        List<PowerV2> originalPowers = credentialV2.credentialSubjectV2().mandate().power();
        List<PowerV2> normalizedPowers = originalPowers.stream()
                .map(power -> PowerV2.builder()
                        .id(power.id())
                        .action(power.action())
                        .domain(power.domain())
                        .function(power.function())
                        .type(power.type())
                        .tmfAction(power.action())
                        .tmfDomain(power.domain())
                        .tmfFunction(power.function())
                        .tmfType(power.type())
                        .build())
                .toList();

        // Build a normalized Mandate using the normalized mandatee and powers
        return LEARCredentialEmployeeV2.builder()
                .context(credentialV2.context())
                .id(credentialV2.id())
                .type(credentialV2.type())
                .description(credentialV2.description())
                .issuer(credentialV2.issuer())
                .validFrom(credentialV2.validFrom())
                .validUntil(credentialV2.validUntil())
                .credentialSubjectV2(CredentialSubjectV2.builder()
                        .mandate(MandateV2.builder()
                                .id(credentialV2.credentialSubjectV2().mandate().id())
                                .mandatee(normalizedMandatee)
                                .power(normalizedPowers)
                                .mandator(credentialV2.credentialSubjectV2().mandate().mandator())
                                .build())
                        .build())
                .build();
    }

    /**
     * FIXME: Temporary workaround to normalize LEAR V3 credential for compatibility.
     * This function copies V3 attributes into their legacy counterparts.
     */
//    private LEARCredentialEmployee normalizeLearCredentialEmployeeV3(LEARCredentialEmployeeV3 credentialV3) {
//        // Cast the mandatee to MandateeV3
//        MandateeV3 originalMandatee = credentialV3.credentialSubjectV3().mandate().mandatee();
//        MandateeV3 normalizedMandatee = MandateeV3.builder()
//                .id(originalMandatee.id())
//                .employeeId(originalMandatee.employeeId())
//                .email(originalMandatee.email())
//                .firstName(originalMandatee.firstName())
//                .lastName(originalMandatee.lastName())
//                .firstNameV1(originalMandatee.firstName())
//                .lastNameV1(originalMandatee.lastName())
//                .build();
//
//        // Mandator: emailAddress legacy
//        MandatorV3 srcMandator = credentialV3.credentialSubjectV3().mandate().mandator();
//        MandatorV3 normalizedMandator = MandatorV3.builder()
//                .id(srcMandator.id())
//                .commonName(srcMandator.commonName())
//                .organizationIdentifier(srcMandator.organizationIdentifier())
//                .organization(srcMandator.organization())
//                .country(srcMandator.country())
//                .serialNumber(srcMandator.serialNumber())
//                .email(srcMandator.email())
//                .emailAddress(srcMandator.email())
//                .build();
//
//        // Normalize each PowerV3: duplicate values into tmf_* fields for compatibility
//        List<PowerV3> originalPowers = credentialV3.credentialSubjectV3().mandate().power();
//        List<PowerV3> normalizedPowers = originalPowers.stream()
//                .map(power -> PowerV3.builder()
//                        .action(power.action())
//                        .domain(power.domain())
//                        .function(power.function())
//                        .type(power.type())
//                        .tmfAction(power.action())
//                        .tmfDomain(power.domain())
//                        .tmfFunction(power.function())
//                        .tmfType(power.type())
//                        .build())
//                .toList();
//
//        // Build a normalized Mandate using the normalized mandatee and powers
//        return LEARCredentialEmployeeV3.builder()
//                .context(credentialV3.context())
//                .id(credentialV3.id())
//                .type(credentialV3.type())
//                .description(credentialV3.description())
//                .issuer(credentialV3.issuer())
//                .validFrom(credentialV3.validFrom())
//                .validUntil(credentialV3.validUntil())
//                .credentialSubjectV3(CredentialSubjectV3.builder()
//                        .mandate(MandateV3.builder()
//                                .mandatee(normalizedMandatee)
//                                .power(normalizedPowers)
//                                .mandator(normalizedMandator)
//                                .build())
//                        .build())
//                .build();
//    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication)
                || OAuth2ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication)
                || OAuth2RefreshTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }
}