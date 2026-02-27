package es.in2.vcverifier.verifier.domain.model.sdjwt;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;

/**
 * SD-JWT Disclosure per SD-JWT VC specification.
 * A disclosure is a base64url-encoded JSON array: [salt, claim_name, claim_value].
 */
public record Disclosure(
        String salt,
        String claimName,
        Object claimValue,
        String encoded
) {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Parse a disclosure from its base64url-encoded form.
     */
    public static Disclosure parse(String encoded) {
        if (encoded == null || encoded.isBlank()) {
            throw new IllegalArgumentException("Disclosure string cannot be null or blank");
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(encoded);
            List<?> array = MAPPER.readValue(decoded, List.class);
            if (array.size() != 3) {
                throw new IllegalArgumentException(
                        "Disclosure must be a 3-element array, got " + array.size());
            }
            return new Disclosure(
                    (String) array.get(0),
                    (String) array.get(1),
                    array.get(2),
                    encoded
            );
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse disclosure: " + e.getMessage(), e);
        }
    }

    /**
     * Compute the SHA-256 digest of this disclosure (for _sd array in JWT).
     * Uses ASCII encoding of the base64url string as per SD-JWT spec.
     */
    public String digest() {
        return digest("SHA-256");
    }

    /**
     * Compute the digest of this disclosure using the specified algorithm.
     */
    public String digest(String algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] hash = md.digest(encoded.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unsupported hash algorithm: " + algorithm, e);
        }
    }
}
