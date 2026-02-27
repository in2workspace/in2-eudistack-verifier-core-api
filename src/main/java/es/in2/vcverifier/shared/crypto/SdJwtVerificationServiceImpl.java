package es.in2.vcverifier.shared.crypto;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.domain.exception.JWTVerificationException;
import es.in2.vcverifier.verifier.domain.model.sdjwt.Disclosure;
import es.in2.vcverifier.verifier.domain.model.sdjwt.SdJwt;
import es.in2.vcverifier.verifier.domain.model.sdjwt.SdJwtVerificationResult;
import es.in2.vcverifier.shared.crypto.DIDService;
import es.in2.vcverifier.shared.crypto.SdJwtVerificationService;
import es.in2.vcverifier.verifier.domain.service.TrustFrameworkService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.*;

/**
 * Full SD-JWT VC verification pipeline:
 * 1. Parse compact SD-JWT
 * 2. Verify issuer JWT signature (DID-based or x5c)
 * 3. Validate disclosure digests against _sd array
 * 4. Validate time window (iat, exp)
 * 5. Validate KB-JWT (signature, aud, nonce, sd_hash)
 * 6. Resolve disclosed claims
 * 7. Validate issuer trust
 */
@Slf4j
@RequiredArgsConstructor
public class SdJwtVerificationServiceImpl implements SdJwtVerificationService {

    private final DIDService didService;
    private final TrustFrameworkService trustFrameworkService;

    @Override
    public SdJwtVerificationResult verifyPresentation(String sdJwtCompact, String expectedAud, String expectedNonce) {
        log.info("Verifying SD-JWT VC presentation");

        // 1. Parse
        SdJwt sdJwt = SdJwt.parse(sdJwtCompact);
        log.debug("Parsed SD-JWT: {} disclosures, KB-JWT present: {}",
                sdJwt.disclosures().size(), sdJwt.keyBindingJwt() != null);

        try {
            SignedJWT issuerJwt = SignedJWT.parse(sdJwt.issuerJwt());
            JWTClaimsSet claims = issuerJwt.getJWTClaimsSet();

            // 2. Verify issuer JWT signature
            verifyIssuerSignature(issuerJwt, claims);

            // 3. Validate disclosure digests
            validateDisclosureDigests(sdJwt.disclosures(), claims);

            // 4. Validate time window
            validateTimeWindow(claims);

            // 5. Validate KB-JWT
            ECKey holderKey = extractHolderKey(claims);
            if (sdJwt.keyBindingJwt() != null) {
                validateKeyBindingJwt(sdJwt, holderKey, expectedAud, expectedNonce);
            } else {
                log.warn("No KB-JWT present in SD-JWT presentation — skipping holder binding check");
            }

            // 6. Resolve claims
            Map<String, Object> resolved = resolveClaims(claims, sdJwt.disclosures());

            // 7. Validate issuer trust
            String issuer = claims.getIssuer();
            if (issuer != null) {
                log.debug("Validating issuer trust for: {}", issuer);
                trustFrameworkService.getTrustedIssuerListData(issuer);
            }

            String vct = (String) claims.getClaim("vct");
            log.info("SD-JWT VC verified successfully. vct={}, issuer={}", vct, issuer);

            return new SdJwtVerificationResult(resolved, vct, holderKey);

        } catch (JWTVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new JWTVerificationException("SD-JWT verification failed: " + e.getMessage(), e);
        }
    }

    private void verifyIssuerSignature(SignedJWT issuerJwt, JWTClaimsSet claims) throws Exception {
        String issuer = claims.getIssuer();
        JWSHeader header = issuerJwt.getHeader();

        // Try DID-based key resolution
        if (issuer != null && issuer.startsWith("did:")) {
            log.debug("Resolving issuer public key from DID: {}", issuer);
            PublicKey publicKey = didService.getPublicKeyFromDid(issuer);
            ECDSAVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKey);
            if (!issuerJwt.verify(verifier)) {
                throw new JWTVerificationException("SD-JWT issuer signature verification failed for DID: " + issuer);
            }
            log.debug("Issuer signature verified via DID");
            return;
        }

        // Try x5c header (certificate chain)
        List<com.nimbusds.jose.util.Base64> x5c = header.getX509CertChain();
        if (x5c != null && !x5c.isEmpty()) {
            log.debug("Resolving issuer public key from x5c header");
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            byte[] certBytes = x5c.get(0).decode();
            java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) cf.generateCertificate(
                    new java.io.ByteArrayInputStream(certBytes));
            PublicKey publicKey = cert.getPublicKey();
            ECDSAVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKey);
            if (!issuerJwt.verify(verifier)) {
                throw new JWTVerificationException("SD-JWT issuer signature verification failed via x5c");
            }
            log.debug("Issuer signature verified via x5c certificate");
            return;
        }

        throw new JWTVerificationException(
                "Cannot verify SD-JWT issuer signature: no DID issuer and no x5c header found");
    }

    @SuppressWarnings("unchecked")
    private void validateDisclosureDigests(List<Disclosure> disclosures, JWTClaimsSet claims) throws Exception {
        List<String> sdDigests = (List<String>) claims.getClaim("_sd");
        if (sdDigests == null) {
            sdDigests = List.of();
        }

        String algorithm = "SHA-256";
        String sdAlg = (String) claims.getClaim("_sd_alg");
        if (sdAlg != null && !sdAlg.isBlank()) {
            algorithm = sdAlg;
        }

        for (Disclosure disclosure : disclosures) {
            String digest = disclosure.digest(algorithm);
            if (!sdDigests.contains(digest)) {
                throw new JWTVerificationException(
                        "Disclosure digest not found in _sd array: " + disclosure.claimName());
            }
        }
        log.debug("All {} disclosure digests validated against _sd array", disclosures.size());
    }

    private void validateTimeWindow(JWTClaimsSet claims) {
        Instant now = Instant.now();

        Date expirationTime = claims.getExpirationTime();
        if (expirationTime != null && now.isAfter(expirationTime.toInstant())) {
            throw new JWTVerificationException("SD-JWT has expired at " + expirationTime);
        }

        Date notBefore = claims.getNotBeforeTime();
        if (notBefore != null && now.isBefore(notBefore.toInstant())) {
            throw new JWTVerificationException("SD-JWT is not yet valid, nbf=" + notBefore);
        }

        log.debug("Time window validated");
    }

    @SuppressWarnings("unchecked")
    private ECKey extractHolderKey(JWTClaimsSet claims) throws Exception {
        Map<String, Object> cnf = (Map<String, Object>) claims.getClaim("cnf");
        if (cnf == null) {
            log.debug("No cnf claim found in SD-JWT — no holder binding key");
            return null;
        }

        Map<String, Object> jwk = (Map<String, Object>) cnf.get("jwk");
        if (jwk == null) {
            log.debug("No jwk in cnf claim");
            return null;
        }

        return ECKey.parse(jwk);
    }

    private void validateKeyBindingJwt(SdJwt sdJwt, ECKey holderKey, String expectedAud, String expectedNonce)
            throws Exception {
        if (holderKey == null) {
            throw new JWTVerificationException("KB-JWT present but no holder key (cnf.jwk) in issuer JWT");
        }

        SignedJWT kbJwt = SignedJWT.parse(sdJwt.keyBindingJwt());

        // Verify KB-JWT signature against holder key
        ECDSAVerifier verifier = new ECDSAVerifier(holderKey.toPublicJWK());
        if (!kbJwt.verify(verifier)) {
            throw new JWTVerificationException("KB-JWT signature verification failed");
        }
        log.debug("KB-JWT signature verified");

        JWTClaimsSet kbClaims = kbJwt.getJWTClaimsSet();

        // Verify audience
        List<String> audiences = kbClaims.getAudience();
        if (audiences == null || audiences.isEmpty() || !audiences.contains(expectedAud)) {
            throw new JWTVerificationException(
                    "KB-JWT aud mismatch. expected=" + expectedAud + ", actual=" + audiences);
        }

        // Verify nonce
        String nonce = (String) kbClaims.getClaim("nonce");
        if (nonce == null || !nonce.equals(expectedNonce)) {
            throw new JWTVerificationException(
                    "KB-JWT nonce mismatch. expected=" + expectedNonce + ", actual=" + nonce);
        }

        // Verify sd_hash
        String expectedSdHash = sdJwt.computeSdHash();
        String actualSdHash = (String) kbClaims.getClaim("sd_hash");
        if (actualSdHash == null || !actualSdHash.equals(expectedSdHash)) {
            throw new JWTVerificationException(
                    "KB-JWT sd_hash mismatch. expected=" + expectedSdHash + ", actual=" + actualSdHash);
        }

        // Verify iat exists
        if (kbClaims.getIssueTime() == null) {
            throw new JWTVerificationException("KB-JWT missing required iat claim");
        }

        log.debug("KB-JWT fully validated: aud, nonce, sd_hash, iat all OK");
    }

    private Map<String, Object> resolveClaims(JWTClaimsSet claims, List<Disclosure> disclosures) {
        Map<String, Object> resolved = new LinkedHashMap<>(claims.getClaims());

        // Remove SD-JWT internal claims
        resolved.remove("_sd");
        resolved.remove("_sd_alg");
        resolved.remove("cnf");

        // Add disclosed claims
        for (Disclosure disclosure : disclosures) {
            resolved.put(disclosure.claimName(), disclosure.claimValue());
        }

        return resolved;
    }
}
