package es.in2.vcverifier.verifier.application.workflow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.verifier.domain.service.VpService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VerifyPresentationWorkflowTest {

    @Mock
    private VpService vpService;

    @InjectMocks
    private VerifyPresentationWorkflow workflow;

    private static final String VP_TOKEN = "eyJhbGciOiJFUzI1NiJ9.test.signature";

    @Test
    @DisplayName("execute() validates VP and returns extracted credential")
    void execute_validatesAndExtractsCredential() {
        JsonNode expectedCredential = new ObjectMapper().createObjectNode().put("type", "LEARCredentialEmployee");
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(VP_TOKEN)).thenReturn(expectedCredential);

        JsonNode result = workflow.execute(VP_TOKEN);

        assertThat(result).isEqualTo(expectedCredential);
        verify(vpService).validateVerifiablePresentation(VP_TOKEN);
        verify(vpService).getCredentialFromTheVerifiablePresentationAsJsonNode(VP_TOKEN);
    }

    @Test
    @DisplayName("execute() propagates exception when VP validation fails")
    void execute_propagatesExceptionWhenValidationFails() {
        doThrow(new RuntimeException("Invalid VP")).when(vpService).validateVerifiablePresentation(VP_TOKEN);

        assertThatThrownBy(() -> workflow.execute(VP_TOKEN))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Invalid VP");

        verify(vpService).validateVerifiablePresentation(VP_TOKEN);
        verify(vpService, never()).getCredentialFromTheVerifiablePresentationAsJsonNode(any());
    }
}
