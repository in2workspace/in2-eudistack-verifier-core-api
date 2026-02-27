package es.in2.vcverifier.verifier.domain.model.credentials;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public record DetailedIssuer(
        @JsonProperty("id") String id,
        @JsonProperty("organizationIdentifier") String organizationIdentifier,
        @JsonProperty("organization") String organization,
        @JsonProperty("country") String country,
        @JsonProperty("commonName") String commonName,
        @JsonProperty("emailAddress") String emailAddress,
        @JsonProperty("serialNumber") String serialNumber
) implements Issuer {
    @Override
    public String getId() {
        return id;
    }
}
