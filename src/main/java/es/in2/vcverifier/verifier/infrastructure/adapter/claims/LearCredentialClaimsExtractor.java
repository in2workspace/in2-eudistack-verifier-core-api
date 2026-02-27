package es.in2.vcverifier.verifier.infrastructure.adapter.claims;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;
import es.in2.vcverifier.verifier.domain.service.ClaimsExtractor;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;

/**
 * Extracts claims from LEAR Credentials (Employee and Machine, all versions)
 * using JSON path navigation with coalesce for field name differences across versions.
 * <p>
 * Replaces the instanceof chain pattern in CustomAuthenticationProvider.
 */
@Slf4j
public class LearCredentialClaimsExtractor implements ClaimsExtractor {

    @Override
    public boolean supports(String credentialType) {
        return "LEARCredentialEmployee".equals(credentialType)
                || "LEARCredentialMachine".equals(credentialType);
    }

    @Override
    public ExtractedClaims extract(JsonNode credential) {
        JsonNode mandatee = credential.at("/credentialSubject/mandate/mandatee");
        JsonNode mandator = credential.at("/credentialSubject/mandate/mandator");

        String subjectDid = resolveSubjectDid(credential, mandatee);
        String mandatorOrgId = coalesce(
                mandator.path("organizationIdentifier").asText(null)
        );
        String issuerDid = resolveIssuerDid(credential);

        // Determine credential type for scope
        String credentialType = extractCredentialType(credential);
        boolean isEmployee = "LEARCredentialEmployee".equals(credentialType);

        String scope = isEmployee ? "openid learcredential" : "machine learcredential";

        // ID Token claims (OpenID Connect standard claims for employees)
        Map<String, Object> idTokenClaims = new HashMap<>();
        if (isEmployee) {
            String firstName = coalesce(
                    mandatee.path("firstName").asText(null),
                    mandatee.path("first_name").asText(null)
            );
            String lastName = coalesce(
                    mandatee.path("lastName").asText(null),
                    mandatee.path("last_name").asText(null)
            );
            String email = mandatee.path("email").asText(null);

            if (firstName != null && lastName != null) {
                idTokenClaims.put("name", firstName + " " + lastName);
                idTokenClaims.put("given_name", firstName);
                idTokenClaims.put("family_name", lastName);
            }
            if (email != null) {
                idTokenClaims.put("email", email);
                idTokenClaims.put("email_verified", true);
            }
        }

        // Access token: full credential as "vc" claim (handled by caller)
        Map<String, Object> accessTokenClaims = new HashMap<>();

        return ExtractedClaims.builder()
                .subjectDid(subjectDid)
                .mandatorOrgId(mandatorOrgId)
                .issuerDid(issuerDid)
                .idTokenClaims(idTokenClaims)
                .accessTokenClaims(accessTokenClaims)
                .scope(scope)
                .build();
    }

    private String resolveSubjectDid(JsonNode credential, JsonNode mandatee) {
        // Priority 1: credentialSubject.id
        String csId = credential.at("/credentialSubject/id").asText(null);
        if (csId != null && !csId.isBlank()) {
            return csId;
        }

        // Priority 2: mandatee.id
        String mandateeId = mandatee.path("id").asText(null);
        if (mandateeId != null && !mandateeId.isBlank()) {
            return mandateeId;
        }

        log.warn("Cannot resolve subject DID from credential JSON paths");
        return null;
    }

    private String resolveIssuerDid(JsonNode credential) {
        // W3C VCDM: issuer as string or object with id
        JsonNode issuerNode = credential.path("issuer");
        if (issuerNode.isTextual()) {
            return issuerNode.asText();
        }
        if (issuerNode.isObject()) {
            return issuerNode.path("id").asText(null);
        }
        // SD-JWT VC: iss claim at top level
        JsonNode issNode = credential.path("iss");
        if (issNode.isTextual()) {
            return issNode.asText();
        }
        return null;
    }

    private String extractCredentialType(JsonNode credential) {
        // W3C VCDM: type array
        JsonNode typeNode = credential.get("type");
        if (typeNode != null && typeNode.isArray()) {
            for (JsonNode t : typeNode) {
                String type = t.asText();
                if (!"VerifiableCredential".equals(type) && !"VerifiableAttestation".equals(type)) {
                    return type;
                }
            }
        }
        // SD-JWT VC: vct claim
        JsonNode vctNode = credential.get("vct");
        if (vctNode != null && vctNode.isTextual()) {
            String vct = vctNode.asText();
            if (vct.contains("LEARCredentialEmployee") || vct.contains("lear_credential_employee")) {
                return "LEARCredentialEmployee";
            }
            if (vct.contains("LEARCredentialMachine") || vct.contains("lear_credential_machine")) {
                return "LEARCredentialMachine";
            }
            return vct;
        }
        return "Unknown";
    }

    @SafeVarargs
    private static <T> T coalesce(T... values) {
        for (T val : values) {
            if (val != null) {
                return val;
            }
        }
        return null;
    }
}
