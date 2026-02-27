package es.in2.vcverifier.oauth2.application.workflow;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.verifier.domain.model.enums.LEARCredentialType;
import es.in2.vcverifier.oauth2.domain.service.ClientAssertionValidationService;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.verifier.domain.service.VpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Application workflow that validates a client_credentials grant (M2M flow).
 * Parses the client_assertion JWT, extracts and validates the embedded VP token,
 * ensures the credential is a LEARCredentialMachine, and validates the assertion claims.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ClientCredentialsValidationWorkflow {

    private final JWTService jwtService;
    private final ClientAssertionValidationService clientAssertionValidationService;
    private final VpService vpService;

    /**
     * Validates an M2M client_credentials grant by:
     * 1. Parsing the client_assertion JWT and extracting the vp_token claim
     * 2. Extracting the credential from the VP
     * 3. Validating that the credential type is LEARCredentialMachine
     * 4. Validating the client_assertion JWT claims
     * 5. Validating the VP (full pipeline)
     *
     * @param clientId        the client identifier
     * @param clientAssertion the client_assertion JWT containing the VP
     * @return the validated credential as a JsonNode
     */
    public JsonNode execute(String clientId, String clientAssertion) {
        log.info("ClientCredentialsValidationWorkflow: validating M2M grant");

        SignedJWT signedJWT = jwtService.parseJWT(clientAssertion);
        Payload payload = jwtService.getPayloadFromSignedJWT(signedJWT);
        String vpToken = jwtService.getClaimFromPayload(payload, "vp_token");
        String decodedVpToken = new String(Base64.getDecoder().decode(vpToken), StandardCharsets.UTF_8);

        // Extract and validate credential type
        JsonNode vc = vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(decodedVpToken);
        List<String> types = extractTypes(vc);
        if (!types.contains(LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue())) {
            log.error("Invalid credential type. Expected: {}", LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue());
            throw new InvalidCredentialTypeException("Invalid LEARCredentialType. Expected LEARCredentialMachine");
        }

        // Validate client assertion JWT claims
        boolean isValid = clientAssertionValidationService.validateClientAssertionJWTClaims(clientId, payload);
        if (!isValid) {
            log.error("JWT claims from client_assertion are invalid");
            throw new IllegalArgumentException("Invalid JWT claims from assertion");
        }

        // Full VP validation
        vpService.validateVerifiablePresentation(decodedVpToken);
        log.info("ClientCredentialsValidationWorkflow: VP validated successfully");

        return vc;
    }

    private static List<String> extractTypes(JsonNode vc) {
        JsonNode typeNode = vc.get("type");
        if (typeNode == null || !typeNode.isArray()) {
            return List.of();
        }
        List<String> types = new ArrayList<>();
        for (JsonNode t : typeNode) {
            types.add(t.asText());
        }
        return types;
    }
}
