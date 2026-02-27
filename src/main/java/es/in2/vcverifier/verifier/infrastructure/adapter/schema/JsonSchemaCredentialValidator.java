package es.in2.vcverifier.verifier.infrastructure.adapter.schema;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.ValidationMessage;
import es.in2.vcverifier.verifier.domain.model.validation.ValidationResult;
import es.in2.vcverifier.verifier.domain.service.CredentialSchemaResolver;
import es.in2.vcverifier.verifier.domain.service.CredentialValidator;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * Validates credentials against JSON Schemas resolved by the chain of CredentialSchemaResolvers.
 */
@Slf4j
public class JsonSchemaCredentialValidator implements CredentialValidator {

    private final List<CredentialSchemaResolver> resolvers;

    public JsonSchemaCredentialValidator(List<CredentialSchemaResolver> resolvers) {
        this.resolvers = resolvers.stream()
                .sorted(Comparator.comparingInt(CredentialSchemaResolver::order))
                .toList();
    }

    @Override
    public ValidationResult validate(JsonNode credential) {
        String credentialType = extractCredentialType(credential);
        List<String> context = extractContext(credential);
        String version = LocalSchemaResolver.resolveVersion(credentialType, context);

        log.debug("Validating credential: type={}, version={}", credentialType, version);

        // Try each resolver in order
        Optional<JsonSchema> schema = Optional.empty();
        for (CredentialSchemaResolver resolver : resolvers) {
            schema = resolver.resolve(credentialType, context, credential);
            if (schema.isPresent()) {
                log.debug("Schema resolved by {} (order={})", resolver.getClass().getSimpleName(), resolver.order());
                break;
            }
        }

        if (schema.isEmpty()) {
            log.warn("No JSON Schema found for credential type={}, context={}. Skipping schema validation.", credentialType, context);
            // No schema found — pass through without schema validation
            return ValidationResult.builder()
                    .valid(true)
                    .credentialType(credentialType)
                    .version(version)
                    .credential(credential)
                    .errors(List.of())
                    .build();
        }

        Set<ValidationMessage> errors = schema.get().validate(credential);
        if (errors.isEmpty()) {
            log.info("Credential validated successfully against schema: type={}, version={}", credentialType, version);
            return ValidationResult.builder()
                    .valid(true)
                    .credentialType(credentialType)
                    .version(version)
                    .credential(credential)
                    .errors(List.of())
                    .build();
        } else {
            List<String> errorMessages = errors.stream()
                    .map(ValidationMessage::getMessage)
                    .toList();
            log.warn("Credential validation failed: type={}, version={}, errors={}", credentialType, version, errorMessages);
            return ValidationResult.builder()
                    .valid(false)
                    .credentialType(credentialType)
                    .version(version)
                    .credential(credential)
                    .errors(errorMessages)
                    .build();
        }
    }

    private String extractCredentialType(JsonNode credential) {
        JsonNode typeNode = credential.get("type");
        if (typeNode != null && typeNode.isArray()) {
            for (JsonNode t : typeNode) {
                String type = t.asText();
                if (!"VerifiableCredential".equals(type) && !"VerifiableAttestation".equals(type)) {
                    return type;
                }
            }
        }
        return "Unknown";
    }

    private List<String> extractContext(JsonNode credential) {
        JsonNode contextNode = credential.get("@context");
        if (contextNode != null && contextNode.isArray()) {
            List<String> context = new ArrayList<>();
            for (JsonNode c : contextNode) {
                context.add(c.asText());
            }
            return context;
        }
        return List.of();
    }
}
