package es.in2.vcverifier.model.credentials.lear.machine.subject.mandate;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.model.credentials.lear.LifeSpan;
import es.in2.vcverifier.model.credentials.lear.Mandator;
import es.in2.vcverifier.model.credentials.lear.Signer;
import es.in2.vcverifier.model.credentials.lear.machine.subject.mandate.mandatee.MandateeV1;
import es.in2.vcverifier.model.credentials.lear.machine.subject.mandate.power.PowerV1;
import lombok.Builder;

import java.util.List;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record MandateV1(
        @JsonProperty("id") String id,
        @JsonProperty("life_span") LifeSpan lifeSpan,
        @JsonProperty("mandatee") MandateeV1 mandatee,
        @JsonProperty("mandator") Mandator mandator,
        @JsonProperty("power") List<PowerV1> power,
        @JsonProperty("signer") Signer signer
) {}
