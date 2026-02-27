package es.in2.vcverifier.oauth2.domain.model;

import lombok.Builder;

@Builder
public record AuthenticationRequestClientData (
        String redirectUri,
        String clientId
){
}
