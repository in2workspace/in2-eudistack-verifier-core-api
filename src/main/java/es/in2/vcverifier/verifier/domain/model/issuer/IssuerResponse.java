package es.in2.vcverifier.verifier.domain.model.issuer;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

@Builder
public record IssuerResponse (
        @JsonProperty("did")
        String did,
        @JsonProperty("attributes")
        List<IssuerAttribute> attributes
){
}
