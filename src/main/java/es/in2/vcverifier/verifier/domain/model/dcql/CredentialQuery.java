package es.in2.vcverifier.verifier.domain.model.dcql;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialQuery(
        @JsonProperty("id") String id,
        @JsonProperty("format") String format,
        @JsonProperty("meta") CredentialMeta meta,
        @JsonProperty("claims") List<ClaimQuery> claims
) {

    public static final String FORMAT_DC_SD_JWT = "dc+sd-jwt";
    public static final String FORMAT_JWT_VC_JSON = "jwt_vc_json";

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CredentialMeta(
            @JsonProperty("vct_values") List<String> vctValues,
            @JsonProperty("credential_definition") CredentialDefinition credentialDefinition
    ) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CredentialDefinition(
            @JsonProperty("type") List<String> type
    ) {
    }
}
