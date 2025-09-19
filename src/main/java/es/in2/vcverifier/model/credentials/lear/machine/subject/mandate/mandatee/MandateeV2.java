package es.in2.vcverifier.model.credentials.lear.machine.subject.mandate.mandatee;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record MandateeV2(
        @JsonProperty("id") String id,
        @JsonProperty("domain") String domain,
        @JsonProperty("ipAddress") String ipAddress
) {}

