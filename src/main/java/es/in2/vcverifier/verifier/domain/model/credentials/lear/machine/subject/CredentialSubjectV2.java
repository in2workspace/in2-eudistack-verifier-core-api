package es.in2.vcverifier.verifier.domain.model.credentials.lear.machine.subject;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.machine.subject.mandate.MandateV2;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialSubjectV2(
        @JsonProperty("mandate") MandateV2 mandate,
        @JsonProperty("id") String id
) {}
