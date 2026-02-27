package es.in2.vcverifier.oauth2.infrastructure.adapter;

import com.nimbusds.jose.Payload;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.JtiTokenCache;
import es.in2.vcverifier.oauth2.domain.service.ClientAssertionValidationService;
import es.in2.vcverifier.shared.crypto.JWTService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class ClientAssertionValidationServiceImpl implements ClientAssertionValidationService {

    private final BackendConfig backendConfig;
    private final JtiTokenCache jtiTokenCache;
    private final JWTService jwtService;

    @Override
    public boolean validateClientAssertionJWTClaims(String clientId, Payload payload) {
        log.info("Starting client assertion JWT claims validation for clientId: {}", clientId);
        return validateIssuerAndSubject(clientId, payload) &&
                validateAudience(payload) &&
                validateJti(payload) &&
                validateExpiration(payload);
    }

    private boolean validateIssuerAndSubject(String clientId, Payload payload) {
        return validateIfIssuerMatchesWithClientId(clientId, payload) && validateIfSubjectMatchesWithClientId(clientId, payload);
    }

    private boolean validateIfIssuerMatchesWithClientId(String clientId, Payload payload) {
        log.debug("ClientAssertionValidationServiceImpl -- validateIfIssuerMatchesWithClientId -- Checking if 'iss' (issuer) matches clientId: {}", clientId);
        String iss = jwtService.getClaimFromPayload(payload, "iss");
        if (!iss.equals(clientId)) {
            log.error("VpValidationServiceImpl -- validateIssuer -- The 'iss' (issuer) claim does not match the clientId.");
            return false;
        }
        log.info("ClientAssertionValidation -- 'iss' (issuer) claim matches clientId: {}", clientId);
        return true;
    }

    private boolean validateIfSubjectMatchesWithClientId(String clientId, Payload payload) {
        log.debug("ClientAssertionValidationServiceImpl -- validateIfSubjectMatchesWithClientId -- Checking if 'sub' (subject) matches clientId: {}", clientId);
        String sub = jwtService.getClaimFromPayload(payload, "sub");
        if (!sub.equals(clientId)) {
            log.error("VpValidationServiceImpl -- validateSubject -- The 'sub' (subject) claim does not match the clientId.");
            return false;
        }
        log.info("ClientAssertionValidation -- 'sub' (subject) claim matches clientId: {}", clientId);
        return true;
    }

    private boolean validateAudience(Payload payload) {
        log.debug("ClientAssertionValidationServiceImpl -- validateAudience -- Validating 'aud' (audience) claim against expected audience");
        String aud = jwtService.getClaimFromPayload(payload, "aud");
        String expectedAudience = backendConfig.getUrl();

        if (!aud.equals(expectedAudience)) {
            log.error("VpValidationServiceImpl -- validateAudience -- The 'aud' (audience) claim does not match the expected audience.");
            return false;
        }
        log.info("ClientAssertionValidation -- 'aud' (audience) matches expected audience");
        return true;
    }

    private boolean validateJti(Payload payload) {
        log.debug("ClientAssertionValidationServiceImpl -- validateJti -- Validating 'jti' (JWT ID) for replay prevention");
        String jti = jwtService.getClaimFromPayload(payload, "jti");

        if (jtiTokenCache.isJtiPresent(jti)) {
            log.error("VpValidationServiceImpl -- validateJti -- The token with jti: {} has already been used.", jti);
            return false;
        } else {
            log.info("ClientAssertionValidation -- Adding 'jti' '{}' to cache for future replay prevention", jti);
            jtiTokenCache.addJti(jti);
        }
        return true;
    }

    private boolean validateExpiration(Payload payload) {
        log.debug("ClientAssertionValidationServiceImpl -- validateExpiration -- Validating 'exp' (expiration) claim");
        long exp = jwtService.getExpirationFromPayload(payload);
        long currentTimeInSeconds = System.currentTimeMillis() / 1000;

        if (exp <= currentTimeInSeconds) {
            log.error("VpValidationServiceImpl -- validateExpiration -- The 'exp' (expiration) claim has expired.");
            return false;
        }
        log.info("ClientAssertionValidation -- Expiration validation successful: 'exp' (expiration) is valid");
        return true;
    }
}
