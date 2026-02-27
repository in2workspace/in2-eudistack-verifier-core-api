package es.in2.vcverifier.verifier.domain.model.validation;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;

import java.util.List;

@Builder
public record ValidationResult(
        boolean valid,
        String credentialType,
        String version,
        JsonNode credential,
        List<String> errors
) {}
