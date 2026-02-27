package es.in2.vcverifier.verifier.domain.model.credentials.lear.machine.subject.mandate;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.machine.subject.mandate.mandatee.MandateeV2;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.machine.subject.mandate.mandator.MandatorV2;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.machine.subject.mandate.power.PowerV2;
import lombok.Builder;

import java.util.List;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record MandateV2(
        @JsonProperty("mandatee") MandateeV2 mandatee,
        @JsonProperty("mandator") MandatorV2 mandator,
        @JsonProperty("power") List<PowerV2> power
) {}

