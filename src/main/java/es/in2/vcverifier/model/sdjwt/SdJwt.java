package es.in2.vcverifier.model.sdjwt;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a complete SD-JWT: issuer JWT + disclosures + optional key binding JWT.
 * Serialized format: {@code <issuer-jwt>~<disclosure1>~<disclosure2>~...~<kb-jwt>}
 */
public record SdJwt(
        String issuerJwt,
        List<Disclosure> disclosures,
        String keyBindingJwt
) {

    /**
     * Parse from combined SD-JWT format string.
     * The last non-empty part containing dots is treated as a KB-JWT.
     */
    public static SdJwt parse(String combined) {
        if (combined == null || combined.isBlank()) {
            throw new IllegalArgumentException("SD-JWT string cannot be null or blank");
        }
        if (!combined.contains("~")) {
            throw new IllegalArgumentException("Invalid SD-JWT format: no ~ separator found");
        }

        String[] parts = combined.split("~", -1);

        String jwt = parts[0];
        if (jwt.isBlank()) {
            throw new IllegalArgumentException("Invalid SD-JWT format: issuer JWT is empty");
        }

        // Last part: if non-empty it's the KB-JWT, if empty there's no KB-JWT
        String kbJwt = parts[parts.length - 1].isEmpty() ? null : parts[parts.length - 1];

        int disclosureEnd = kbJwt != null ? parts.length - 1 : parts.length;
        List<Disclosure> disclosures = new ArrayList<>();
        for (int i = 1; i < disclosureEnd; i++) {
            if (!parts[i].isEmpty()) {
                disclosures.add(Disclosure.parse(parts[i]));
            }
        }

        return new SdJwt(jwt, disclosures, kbJwt);
    }

    /**
     * Serialize to the SD-JWT combined format.
     */
    public String serialize() {
        var sb = new StringBuilder(issuerJwt);
        for (Disclosure d : disclosures) {
            sb.append('~').append(d.encoded());
        }
        sb.append('~');
        if (keyBindingJwt != null) {
            sb.append(keyBindingJwt);
        }
        return sb.toString();
    }

    /**
     * Compute the SD hash for KB-JWT verification.
     * The sd_hash is SHA-256 of everything before the KB-JWT (including trailing ~).
     */
    public String computeSdHash() {
        var sb = new StringBuilder(issuerJwt);
        for (Disclosure d : disclosures) {
            sb.append('~').append(d.encoded());
        }
        sb.append('~');
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(sb.toString().getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
