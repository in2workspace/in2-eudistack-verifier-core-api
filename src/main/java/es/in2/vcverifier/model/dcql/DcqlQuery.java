package es.in2.vcverifier.model.dcql;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record DcqlQuery(
        @JsonProperty("credentials") List<CredentialQuery> credentials
) {
}
