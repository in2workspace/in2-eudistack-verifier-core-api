package es.in2.vcverifier.verifier.domain.model.credentials.lear.employee.subject;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.employee.subject.mandate.MandateV3;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialSubjectV3(
        @JsonProperty("mandate") MandateV3 mandate,
        @JsonProperty("id") String id

) {}
