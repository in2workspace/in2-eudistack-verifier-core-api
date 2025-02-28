package es.in2.verifier.model.credentials.lear.employee.subject;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.verifier.model.credentials.lear.employee.subject.mandate.MandateV1;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialSubjectV1(
        @JsonProperty("mandate") MandateV1 mandate
) {}
