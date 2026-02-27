package es.in2.vcverifier.oauth2.domain.model;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

import java.util.Set;

@Builder
public record AuthorizationCodeData(
        String state,
        JsonNode verifiableCredential,
        Set<String> requestedScopes,
        OAuth2Authorization oAuth2Authorization,
        String clientNonce

) {
}
