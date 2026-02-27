package es.in2.vcverifier.verifier.application.workflow;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.verifier.domain.service.VpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Application workflow that validates a Verifiable Presentation and extracts
 * the embedded credential as a JsonNode.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class VerifyPresentationWorkflow {

    private final VpService vpService;

    /**
     * Validates the VP and returns the embedded credential.
     *
     * @param vpToken the raw VP JWT string
     * @return the credential extracted from the VP as a JsonNode
     */
    public JsonNode execute(String vpToken) {
        log.info("VerifyPresentationWorkflow: validating VP");
        vpService.validateVerifiablePresentation(vpToken);
        JsonNode credential = vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(vpToken);
        log.info("VerifyPresentationWorkflow: VP validated and credential extracted");
        return credential;
    }
}
