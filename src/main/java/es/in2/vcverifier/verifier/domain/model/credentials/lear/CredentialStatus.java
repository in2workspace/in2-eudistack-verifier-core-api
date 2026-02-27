package es.in2.vcverifier.verifier.domain.model.credentials.lear;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;


@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialStatus(
        @JsonProperty("id") String id,
        @JsonProperty("type") String type,
        @JsonProperty("statusPurpose") String purpose,
        @JsonProperty("statusListIndex") String index,
        @JsonProperty("statusListCredential") String credentials
) {}

