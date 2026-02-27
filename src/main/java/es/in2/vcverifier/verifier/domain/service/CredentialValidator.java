package es.in2.vcverifier.verifier.domain.service;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.verifier.domain.model.validation.ValidationResult;

/**
 * Validates a credential's structure against its JSON Schema.
 */
public interface CredentialValidator {
    ValidationResult validate(JsonNode credential);
}
