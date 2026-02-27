package es.in2.vcverifier.verifier.application.workflow;

import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.crypto.CryptoComponent;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationRequestJWT;
import es.in2.vcverifier.verifier.domain.exception.InvalidScopeException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static es.in2.vcverifier.shared.domain.util.Constants.AUTHORIZATION_RESPONSE_ENDPOINT;
import static org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames.NONCE;

/**
 * Builds the OID4VP authorization request: validates scope, constructs the JWT payload,
 * generates the openid4vp:// URL, and caches the authorization request JWT.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationRequestBuildWorkflow {

    private final JWTService jwtService;
    private final CryptoComponent cryptoComponent;
    private final BackendConfig backendConfig;
    private final CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;
    private final CacheStore<String> cacheForNonceByState;

    public record Result(String signedAuthRequestJwt, String openid4vpUrl, String nonce, String homeUri) {}

    /**
     * Validates the scope, builds the JWT payload for an OID4VP authorization request,
     * signs it, generates the openid4vp:// redirect URL, and caches the JWT.
     *
     * @param clientName   the registered client's name (used as homeUri)
     * @param scope        the requested scope (must contain "learcredential")
     * @param state        the OAuth2 state parameter
     * @return a Result with the signed JWT, openid4vp URL, nonce and homeUri
     */
    public Result execute(String clientName, String scope, String state) {
        checkScope(scope);

        String nonce = UUID.randomUUID().toString();
        String jwtPayload = buildJwtPayload(scope, state, nonce);
        String signedJwt = jwtService.generateJWTwithOI4VPType(jwtPayload);

        // Cache the auth request JWT keyed by a new nonce for the QR
        String qrNonce = UUID.randomUUID().toString();
        cacheStoreForAuthorizationRequestJWT.add(
                qrNonce,
                AuthorizationRequestJWT.builder().authRequest(signedJwt).build()
        );

        String openid4vpUrl = generateOpenId4VpUrl(qrNonce);

        return new Result(signedJwt, openid4vpUrl, qrNonce, clientName);
    }

    private void checkScope(String scope) {
        if (!scope.contains("learcredential")) {
            throw new InvalidScopeException(
                    "The requested scope does not contain 'learcredential'. Only this scope and 'email', 'profile' are supported.");
        }
    }

    private String buildJwtPayload(String scope, String state, String nonce) {
        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(10, ChronoUnit.DAYS);

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
                .claim("dcql_query", buildDcqlQuery())
                .jwtID(UUID.randomUUID().toString())
                .build();

        cacheForNonceByState.add(state, nonce);
        return payload.toString();
    }

    private Map<String, Object> buildDcqlQuery() {
        return Map.of("credentials", List.of(
                Map.of(
                        "id", "lear_sd_jwt",
                        "format", "dc+sd-jwt",
                        "meta", Map.of("vct_values", List.of("LEARCredentialEmployee"))
                ),
                Map.of(
                        "id", "lear_jwt_vc",
                        "format", "jwt_vc_json",
                        "meta", Map.of("credential_definition", Map.of(
                                "type", List.of("VerifiableCredential", "LEARCredentialEmployee")
                        ))
                )
        ));
    }

    private String generateOpenId4VpUrl(String nonce) {
        String requestUri = String.format("%s/oid4vp/auth-request/%s",
                backendConfig.getUrl(), nonce);
        return String.format("openid4vp://?client_id=%s&request_uri=%s",
                URLEncoder.encode(cryptoComponent.getECKey().getKeyID(), StandardCharsets.UTF_8),
                URLEncoder.encode(requestUri, StandardCharsets.UTF_8));
    }
}
