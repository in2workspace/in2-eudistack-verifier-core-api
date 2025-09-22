package es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.mandator;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record MandatorV3(
        @JsonProperty("id") String id,
        @JsonProperty("commonName") String commonName,
        @JsonProperty("country") String country,
        @JsonProperty("email") String email,
        @JsonProperty("organization") String organization,
        @JsonProperty("organizationIdentifier") String organizationIdentifier,
        @JsonProperty("serialNumber") String serialNumber
        // FIXME: Those fields are here to avoid some components failure due the incompatibility for Lear V3
//        @JsonProperty("emailAddress") String emailAddress
) {}
