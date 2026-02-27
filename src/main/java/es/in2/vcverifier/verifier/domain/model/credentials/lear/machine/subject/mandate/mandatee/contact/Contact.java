package es.in2.vcverifier.verifier.domain.model.credentials.lear.machine.subject.mandate.mandatee.contact;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public record Contact(
        @JsonProperty("email") String email,
        @JsonProperty("phone") String mobilePhone
) {}