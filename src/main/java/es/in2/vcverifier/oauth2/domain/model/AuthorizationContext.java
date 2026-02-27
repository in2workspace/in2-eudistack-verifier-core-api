package es.in2.vcverifier.oauth2.domain.model;

import lombok.Builder;

@Builder
public record AuthorizationContext(
        String state,
        String scope,
        String redirectUri,
        String clientNonce,
        String originalRequestURL,
        String requestUri,
        String codeChallenge,
        String codeChallengeMethod
) {
}
