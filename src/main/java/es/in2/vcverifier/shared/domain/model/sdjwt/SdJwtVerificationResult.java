package es.in2.vcverifier.shared.domain.model.sdjwt;

import com.nimbusds.jose.jwk.ECKey;

import java.util.Map;

/**
 * Result of SD-JWT VC verification.
 *
 * @param resolvedClaims all claims (plain from issuer JWT + disclosed), ready for token generation
 * @param vct            the credential type (from the {@code vct} claim)
 * @param holderKey      the holder's public key from {@code cnf.jwk} (for binding verification)
 */
public record SdJwtVerificationResult(
        Map<String, Object> resolvedClaims,
        String vct,
        ECKey holderKey
) {
}
