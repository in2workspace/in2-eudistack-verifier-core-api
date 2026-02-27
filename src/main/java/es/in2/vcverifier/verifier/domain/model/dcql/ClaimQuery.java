package es.in2.vcverifier.verifier.domain.model.dcql;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ClaimQuery(
        @JsonProperty("path") List<String> path,
        @JsonProperty("values") List<String> values,
        @JsonProperty("essential") Boolean essential
) {
}
