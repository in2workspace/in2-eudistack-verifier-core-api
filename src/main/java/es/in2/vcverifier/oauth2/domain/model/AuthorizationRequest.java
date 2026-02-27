package es.in2.vcverifier.oauth2.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record AuthorizationRequest(
        @JsonProperty("response_type") String responseType,               // Must be "vp_token"
        @JsonProperty("response_mode") String responseMode,               // Must be "direct_post"
        @JsonProperty("response_uri") String responseUri,                 // The URI to send the Authorization Response
        @JsonProperty("scope") String scope,                              // The scope parameter, e.g., "dome.credentials.presentation.LEARCredentialEmployee"
        @JsonProperty("client_id") String clientId,                       // The DID of the Verifier (RP)
        @JsonProperty("client_id_scheme") String clientIdScheme,          // Must be "did"
        @JsonProperty("nonce") String nonce,                              // A unique nonce value
        @JsonProperty("state") String state,                              // The state parameter to associate authentication sessions
        @JsonProperty("presentation_definition") String presentationDefinition,     // Optional: presentation definition JSON object (null if unused)
        @JsonProperty("presentation_definition_uri") String presentationDefinitionUri // Optional: URI for the presentation definition (null if unused)
) {
}
