package es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.power;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record PowerV3(
        @JsonProperty("action") Object action,
        @JsonProperty("domain") String domain,
        @JsonProperty("function") String function,
        @JsonProperty("type") String type
) {}

