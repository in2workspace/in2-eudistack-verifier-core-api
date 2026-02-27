package es.in2.vcverifier.oauth2.application.workflow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.oauth2.domain.service.ClientAssertionValidationService;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.verifier.domain.service.VpService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ClientCredentialsValidationWorkflowTest {

    @Mock private JWTService jwtService;
    @Mock private ClientAssertionValidationService clientAssertionValidationService;
    @Mock private VpService vpService;

    @InjectMocks
    private ClientCredentialsValidationWorkflow workflow;

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String CLIENT_ID = "did:key:z6MkClient";
    private static final String VP_TOKEN_RAW = "eyJhbGciOiJFUzI1NiJ9.vp-payload.signature";
    private static final String VP_TOKEN_B64 = Base64.getEncoder().encodeToString(VP_TOKEN_RAW.getBytes(StandardCharsets.UTF_8));
    private static final String CLIENT_ASSERTION = "client-assertion-jwt";

    private ObjectNode buildMachineCredential() {
        ObjectNode credential = OBJECT_MAPPER.createObjectNode();
        ArrayNode typeArray = credential.putArray("type");
        typeArray.add("VerifiableCredential");
        typeArray.add("LEARCredentialMachine");
        return credential;
    }

    private ObjectNode buildEmployeeCredential() {
        ObjectNode credential = OBJECT_MAPPER.createObjectNode();
        ArrayNode typeArray = credential.putArray("type");
        typeArray.add("VerifiableCredential");
        typeArray.add("LEARCredentialEmployee");
        return credential;
    }

    @Test
    @DisplayName("execute() validates M2M flow and returns credential")
    void execute_validatesAndReturnsCredential() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        ObjectNode credential = buildMachineCredential();

        when(jwtService.parseJWT(CLIENT_ASSERTION)).thenReturn(signedJWT);
        when(jwtService.getPayloadFromSignedJWT(signedJWT)).thenReturn(payload);
        when(jwtService.getClaimFromPayload(payload, "vp_token")).thenReturn(VP_TOKEN_B64);
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(VP_TOKEN_RAW)).thenReturn(credential);
        when(clientAssertionValidationService.validateClientAssertionJWTClaims(eq(CLIENT_ID), eq(payload))).thenReturn(true);

        JsonNode result = workflow.execute(CLIENT_ID, CLIENT_ASSERTION);

        assertThat(result).isEqualTo(credential);
        verify(vpService).validateVerifiablePresentation(VP_TOKEN_RAW);
    }

    @Test
    @DisplayName("execute() throws when credential is not LEARCredentialMachine")
    void execute_throwsForWrongCredentialType() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        ObjectNode credential = buildEmployeeCredential();

        when(jwtService.parseJWT(CLIENT_ASSERTION)).thenReturn(signedJWT);
        when(jwtService.getPayloadFromSignedJWT(signedJWT)).thenReturn(payload);
        when(jwtService.getClaimFromPayload(payload, "vp_token")).thenReturn(VP_TOKEN_B64);
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(VP_TOKEN_RAW)).thenReturn(credential);

        assertThatThrownBy(() -> workflow.execute(CLIENT_ID, CLIENT_ASSERTION))
                .isInstanceOf(InvalidCredentialTypeException.class)
                .hasMessageContaining("LEARCredentialMachine");

        verify(vpService, never()).validateVerifiablePresentation(any());
    }

    @Test
    @DisplayName("execute() throws when client assertion claims are invalid")
    void execute_throwsForInvalidClaims() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        ObjectNode credential = buildMachineCredential();

        when(jwtService.parseJWT(CLIENT_ASSERTION)).thenReturn(signedJWT);
        when(jwtService.getPayloadFromSignedJWT(signedJWT)).thenReturn(payload);
        when(jwtService.getClaimFromPayload(payload, "vp_token")).thenReturn(VP_TOKEN_B64);
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(VP_TOKEN_RAW)).thenReturn(credential);
        when(clientAssertionValidationService.validateClientAssertionJWTClaims(eq(CLIENT_ID), eq(payload))).thenReturn(false);

        assertThatThrownBy(() -> workflow.execute(CLIENT_ID, CLIENT_ASSERTION))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid JWT claims");

        verify(vpService, never()).validateVerifiablePresentation(any());
    }

    @Test
    @DisplayName("execute() propagates VP validation exception")
    void execute_propagatesVpValidationException() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        ObjectNode credential = buildMachineCredential();

        when(jwtService.parseJWT(CLIENT_ASSERTION)).thenReturn(signedJWT);
        when(jwtService.getPayloadFromSignedJWT(signedJWT)).thenReturn(payload);
        when(jwtService.getClaimFromPayload(payload, "vp_token")).thenReturn(VP_TOKEN_B64);
        when(vpService.getCredentialFromTheVerifiablePresentationAsJsonNode(VP_TOKEN_RAW)).thenReturn(credential);
        when(clientAssertionValidationService.validateClientAssertionJWTClaims(eq(CLIENT_ID), eq(payload))).thenReturn(true);
        doThrow(new RuntimeException("VP invalid")).when(vpService).validateVerifiablePresentation(VP_TOKEN_RAW);

        assertThatThrownBy(() -> workflow.execute(CLIENT_ID, CLIENT_ASSERTION))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("VP invalid");
    }
}
