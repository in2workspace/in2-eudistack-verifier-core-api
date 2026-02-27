package es.in2.vcverifier.service;

import es.in2.vcverifier.model.sdjwt.SdJwtVerificationResult;

/**
 * Service for verifying SD-JWT VC presentations.
 * Handles signature verification, disclosure validation, KB-JWT verification,
 * and claim resolution.
 */
public interface SdJwtVerificationService {

    /**
     * Parse, verify, and resolve an SD-JWT VC presentation.
     *
     * @param sdJwtCompact the compact SD-JWT string (issuer-jwt~disc1~disc2~...~kb-jwt)
     * @param expectedAud  the verifier's URL (for KB-JWT aud check)
     * @param expectedNonce the nonce from the authorization request (for KB-JWT nonce check)
     * @return verification result with resolved claims, vct, and holder key
     */
    SdJwtVerificationResult verifyPresentation(String sdJwtCompact, String expectedAud, String expectedNonce);
}
