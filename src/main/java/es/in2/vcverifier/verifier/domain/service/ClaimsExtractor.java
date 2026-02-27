package es.in2.vcverifier.verifier.domain.service;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;

/**
 * SPI for extracting claims from a validated credential for token generation.
 * Implementations handle different credential types (LEARCredential, PID, etc.).
 */
public interface ClaimsExtractor {
    boolean supports(String credentialType);
    ExtractedClaims extract(JsonNode credential);
}
