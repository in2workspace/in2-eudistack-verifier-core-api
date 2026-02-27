package es.in2.vcverifier.verifier.domain.model.credentials;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public record SimpleIssuer(@JsonProperty("id") String id) implements Issuer {

    @JsonValue
    public String toJson() {
        return id;
    }

    @Override
    public String getId() {
        return id;
    }
}
