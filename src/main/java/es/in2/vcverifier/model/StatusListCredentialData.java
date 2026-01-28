package es.in2.vcverifier.model;

import java.util.Objects;

public record StatusListCredentialData(
        String issuer,
        String statusPurpose,
        byte[] rawBitstringBytes
) {
    public StatusListCredentialData {
        Objects.requireNonNull(statusPurpose, "statusPurpose cannot be null");
        Objects.requireNonNull(rawBitstringBytes, "rawBitstringBytes cannot be null");
    }
}

