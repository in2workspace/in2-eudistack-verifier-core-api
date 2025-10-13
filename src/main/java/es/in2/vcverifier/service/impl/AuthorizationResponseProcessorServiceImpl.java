package es.in2.vcverifier.service.impl;

import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.exception.JWTClaimMissingException;
import es.in2.vcverifier.exception.JWTParsingException;
import es.in2.vcverifier.exception.LoginTimeoutException;
import es.in2.vcverifier.model.AuthorizationCodeData;
import es.in2.vcverifier.service.AuthorizationResponseProcessorService;
import es.in2.vcverifier.service.VpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static es.in2.vcverifier.util.Constants.*;
import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationResponseProcessorServiceImpl implements AuthorizationResponseProcessorService {

    private final CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    private final CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;
    private final VpService vpService; // Service responsible for VP validation
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService oAuth2AuthorizationService;
    private final SimpMessagingTemplate messagingTemplate;
    private final CacheStore<String> cacheForNonceByState;

    @Override
    public void processAuthResponse(String state, String vpToken){
        log.info("Processing authorization response");

        // Validate if the state exists in the cache
        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = cacheStoreForOAuth2AuthorizationRequest.get(state);

        // Remove the state from cache after retrieving the Object
        cacheStoreForOAuth2AuthorizationRequest.delete(state);

        Instant issueTime = Instant.now();

        Object expirationLoginValue = oAuth2AuthorizationRequest.getAdditionalParameters().get(EXPIRATION);

        if(expirationLoginValue==null){
            throw new LoginTimeoutException("Start time is missing from login request");
        }

        if (issueTime.getEpochSecond() >= (long) expirationLoginValue) {
            throw new LoginTimeoutException("Login time has expired");
        }
        String redirectUri = oAuth2AuthorizationRequest.getRedirectUri();
        // Decode vpToken from Base64
        String decodedVpToken = new String(Base64.getDecoder().decode(vpToken), StandardCharsets.UTF_8);
        log.info("Decoded VP Token: {}", decodedVpToken);

        // Validates the 'nonce' and 'aud' claims from the VP token against the cached state
        validateVpTokenNonceAndAudience(decodedVpToken, state);

        // Send the decoded token to a service for validation
        try{
            vpService.validateVerifiablePresentation(decodedVpToken);
        }catch(Exception e){
            log.error("VP Token is invalid - VP Token used in H2M flow is invalid");
            throw e;
        }
        log.info("VP Token validated successfully");

        // Generate a code (code)
        String code = UUID.randomUUID().toString();
        log.info("Code generated: {}", code);

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(oAuth2AuthorizationRequest.getClientId());

        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        // Preparar datos para binding + PKCE (si existiera)
        String redirectUriUsed = oAuth2AuthorizationRequest.getRedirectUri();
        var requestedScopes = oAuth2AuthorizationRequest.getScopes();

        var addl = oAuth2AuthorizationRequest.getAdditionalParameters();
        String codeChallenge       = (String) addl.get(PkceParameterNames.CODE_CHALLENGE);
        String codeChallengeMethod = (String) addl.get(PkceParameterNames.CODE_CHALLENGE_METHOD);


        Instant expirationTime = issueTime.plus(Long.parseLong(ACCESS_TOKEN_EXPIRATION_TIME), ChronoUnit.valueOf(ACCESS_TOKEN_EXPIRATION_CHRONO_UNIT));
        // Register the Oauth2Authorization because is needed for verifications
        OAuth2Authorization.Builder authBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(registeredClient.getId())
                .principalName(registeredClient.getClientId())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .token(new OAuth2AuthorizationCode(code, issueTime, expirationTime))
                .attribute(OAuth2AuthorizationRequest.class.getName(), oAuth2AuthorizationRequest);

        if (org.springframework.util.StringUtils.hasText(codeChallenge)) {
            authBuilder.attribute(PkceParameterNames.CODE_CHALLENGE, codeChallenge);
        }
        if (org.springframework.util.StringUtils.hasText(codeChallengeMethod)) {
            authBuilder.attribute(PkceParameterNames.CODE_CHALLENGE_METHOD, codeChallengeMethod);
        }

        System.out.println("XIVATO 3: "+ authBuilder);

        OAuth2Authorization authorization = authBuilder.build();
        oAuth2AuthorizationService.save(authorization);

        log.info("OAuth2Authorization generated");

        // Retrieve nonce from additional parameters
        String nonceValue = (String) oAuth2AuthorizationRequest.getAdditionalParameters().get(NONCE);

        // Create a builder
        AuthorizationCodeData.AuthorizationCodeDataBuilder authCodeDataBuilder = AuthorizationCodeData.builder()
                .state(state)
                .verifiableCredential(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(decodedVpToken))
                .oAuth2Authorization(authorization)
                .requestedScopes(oAuth2AuthorizationRequest.getScopes());

        authCodeDataBuilder.clientNonce(nonceValue);

        // Finally build the object
        AuthorizationCodeData authorizationCodeData = authCodeDataBuilder.build();
        cacheStoreForAuthorizationCodeData.add(code, authorizationCodeData);


        // Build the redirect URL with the code (code) and the state
        String redirectUrl = UriComponentsBuilder.fromHttpUrl(redirectUri)
                .queryParam("code", code)
                .queryParam("state", state)
                .build()
                .toUriString();

        //Perform the redirection using HttpServletResponse
        log.info("Redirecting to URL: {}", redirectUrl);

        // Enviar la URL de redirección al cliente a través del WebSocket
        messagingTemplate.convertAndSend("/oidc/redirection/" + state, redirectUrl);

    }


    private void validateVpTokenNonceAndAudience(String decodedVpToken, String state) {
        if (state == null || state.isBlank()) {
            throw new JWTClaimMissingException("The 'state' claim is missing in the VP token.");
        }
        try {
            SignedJWT vpSignedJWT = SignedJWT.parse(decodedVpToken);
            String vpNonce = vpSignedJWT.getJWTClaimsSet().getClaim(NONCE).toString();
            if (vpNonce == null || vpNonce.isBlank()) {
                throw new JWTClaimMissingException("The 'nonce' claim is missing in the VP token.");
            }
            String cachedNonce = cacheForNonceByState.get(state);
            if (cachedNonce == null) {
                throw new JWTClaimMissingException("No nonce found in cache for state=" + state);
            }
            if (!vpNonce.equals(cachedNonce)) {
                throw new JWTClaimMissingException("VP nonce does not match the cached nonce for the given state.");
            }
            List<String> audiences = vpSignedJWT.getJWTClaimsSet().getAudience();
            if (audiences == null || audiences.isEmpty()) {
                throw new JWTClaimMissingException("The 'aud' claim is missing in the VP token.");
            }
//            TODO This will be fixed with this wallet change
//            String expectedAudience = backendConfig.getUrl();
//            log.info("The aud expected is : {} and the aud recibed is: {}",audiences,expectedAudience);
//            if (!audiences.contains(expectedAudience)) {
//                throw new JWTClaimMissingException("The 'aud' claim in the VP token does not match the expected verifier URL.");
//            }
            log.debug("Validated VP nonce: received={}, cached={}, audience={}", vpNonce, cachedNonce, audiences);
        } catch (ParseException e) {
            throw new JWTParsingException("Failed to parse the VP JWT or extract claims.");
        }
    }

}