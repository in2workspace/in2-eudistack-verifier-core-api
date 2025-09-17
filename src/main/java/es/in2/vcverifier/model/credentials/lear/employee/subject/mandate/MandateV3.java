package es.in2.vcverifier.model.credentials.lear.employee.subject.mandate;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.mandatee.MandateeV3;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.mandator.MandatorV3;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.power.PowerV2;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.power.PowerV3;
import lombok.Builder;

import java.util.List;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record MandateV3(
        //todo remove
        @JsonProperty("id") String id,
        @JsonProperty("mandatee") MandateeV3 mandatee,
        @JsonProperty("mandator") MandatorV3 mandator,
        @JsonProperty("power") List<PowerV3> power
) {}