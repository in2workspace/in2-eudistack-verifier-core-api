package es.in2.vcverifier.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CredentialStatusResponse(
        @JsonProperty("nonce") String credentialNonce) {
}
