package es.in2.vcverifier.verifier.domain.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.JsonSchema;

import java.util.List;
import java.util.Optional;

/**
 * SPI for resolving JSON Schemas for credential validation.
 * Implementations provide schemas from different sources (embedded in VC, local classpath, issuer metadata, etc.).
 */
public interface CredentialSchemaResolver {
    int order();
    Optional<JsonSchema> resolve(String credentialType, List<String> context, JsonNode credential);
}
