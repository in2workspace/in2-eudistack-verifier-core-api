package es.in2.vcverifier.model.validation;

import lombok.Builder;

import java.util.Map;

@Builder
public record ExtractedClaims(
        String subjectDid,
        String mandatorOrgId,
        String issuerDid,
        Map<String, Object> idTokenClaims,
        Map<String, Object> accessTokenClaims,
        String scope
) {}
