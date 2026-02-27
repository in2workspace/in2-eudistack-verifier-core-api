package es.in2.vcverifier.verifier.domain.model.issuer;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

@Builder
public record Claim(
        @JsonProperty("name") String name,
        @JsonProperty("allowedValues") List<Object> allowedValues
) {}
