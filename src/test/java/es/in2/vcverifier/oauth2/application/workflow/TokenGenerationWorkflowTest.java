package es.in2.vcverifier.oauth2.application.workflow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;
import es.in2.vcverifier.verifier.domain.service.ClaimsExtractor;
import es.in2.vcverifier.shared.crypto.JWTService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenGenerationWorkflowTest {

    @Mock private JWTService jwtService;
    @Mock private BackendConfig backendConfig;
    @Mock private ClaimsExtractor claimsExtractor;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private TokenGenerationWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new TokenGenerationWorkflow(jwtService, backendConfig, objectMapper, List.of(claimsExtractor));
    }

    private ObjectNode buildW3cCredential(String credentialType) {
        ObjectNode credential = objectMapper.createObjectNode();
        ArrayNode typeArray = credential.putArray("type");
        typeArray.add("VerifiableCredential");
        typeArray.add(credentialType);
        ObjectNode credentialSubject = credential.putObject("credentialSubject");
        credentialSubject.put("id", "did:key:z6MkSubject");
        return credential;
    }

    private ObjectNode buildSdJwtCredential(String vct) {
        ObjectNode credential = objectMapper.createObjectNode();
        credential.put("vct", vct);
        ObjectNode credentialSubject = credential.putObject("credentialSubject");
        credentialSubject.put("id", "did:key:z6MkSubject");
        return credential;
    }

    @Nested
    @DisplayName("extractCredentialType()")
    class ExtractCredentialTypeTests {
        @Test
        @DisplayName("extracts type from W3C type array")
        void extractsFromW3cTypeArray() {
            ObjectNode credential = buildW3cCredential("LEARCredentialEmployee");
            assertThat(workflow.extractCredentialType(credential)).isEqualTo("LEARCredentialEmployee");
        }

        @Test
        @DisplayName("extracts type from SD-JWT vct field")
        void extractsFromSdJwtVct() {
            ObjectNode credential = buildSdJwtCredential("LEARCredentialEmployee");
            assertThat(workflow.extractCredentialType(credential)).isEqualTo("LEARCredentialEmployee");
        }

        @Test
        @DisplayName("normalizes lear_credential_employee vct to LEARCredentialEmployee")
        void normalizesSnakeCaseVct() {
            ObjectNode credential = buildSdJwtCredential("urn:credential:lear_credential_employee");
            assertThat(workflow.extractCredentialType(credential)).isEqualTo("LEARCredentialEmployee");
        }

        @Test
        @DisplayName("throws when neither type nor vct is present")
        void throwsWhenNoTypeOrVct() {
            ObjectNode credential = objectMapper.createObjectNode();
            assertThatThrownBy(() -> workflow.extractCredentialType(credential))
                    .isInstanceOf(OAuth2AuthenticationException.class);
        }
    }

    @Nested
    @DisplayName("resolveSubjectDid()")
    class ResolveSubjectDidTests {
        @Test
        @DisplayName("returns DID from ClaimsExtractor when available")
        void returnsDidFromExtractor() {
            ExtractedClaims claims = ExtractedClaims.builder().subjectDid("did:key:fromExtractor").scope("openid").build();
            ObjectNode credential = objectMapper.createObjectNode();
            assertThat(workflow.resolveSubjectDid(claims, credential)).isEqualTo("did:key:fromExtractor");
        }

        @Test
        @DisplayName("falls back to credentialSubject.id")
        void fallsBackToCredentialSubjectId() {
            ExtractedClaims claims = ExtractedClaims.builder().scope("openid").build();
            ObjectNode credential = objectMapper.createObjectNode();
            credential.putObject("credentialSubject").put("id", "did:key:fromCS");
            assertThat(workflow.resolveSubjectDid(claims, credential)).isEqualTo("did:key:fromCS");
        }

        @Test
        @DisplayName("falls back to mandatee.id")
        void fallsBackToMandateeId() {
            ExtractedClaims claims = ExtractedClaims.builder().scope("openid").build();
            ObjectNode credential = objectMapper.createObjectNode();
            ObjectNode cs = credential.putObject("credentialSubject");
            ObjectNode mandate = cs.putObject("mandate");
            ObjectNode mandatee = mandate.putObject("mandatee");
            mandatee.put("id", "did:key:fromMandatee");
            assertThat(workflow.resolveSubjectDid(claims, credential)).isEqualTo("did:key:fromMandatee");
        }

        @Test
        @DisplayName("throws when no DID is resolvable")
        void throwsWhenNoDidResolvable() {
            ExtractedClaims claims = ExtractedClaims.builder().scope("openid").build();
            ObjectNode credential = objectMapper.createObjectNode();
            assertThatThrownBy(() -> workflow.resolveSubjectDid(claims, credential))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Missing cryptographic binding DID");
        }
    }

    @Nested
    @DisplayName("execute()")
    class ExecuteTests {
        @Test
        @DisplayName("generates access token and ID token for authorization_code grant")
        void generatesAccessAndIdToken() {
            ObjectNode credential = buildW3cCredential("LEARCredentialEmployee");
            ExtractedClaims claims = ExtractedClaims.builder()
                    .subjectDid("did:key:z6MkSubject")
                    .scope("openid learcredential")
                    .idTokenClaims(Map.of("name", "Test User"))
                    .build();

            when(claimsExtractor.supports("LEARCredentialEmployee")).thenReturn(true);
            when(claimsExtractor.extract(credential)).thenReturn(claims);
            when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
            when(jwtService.generateJWT(anyString())).thenReturn("access-jwt", "id-jwt");

            Map<String, Object> additionalParams = Map.of(
                    OAuth2ParameterNames.SCOPE, "openid learcredential"
            );
            TokenGenerationWorkflow.Result result = workflow.execute(credential, "did:key:client", additionalParams, true);

            assertThat(result.accessTokenJwt()).isEqualTo("access-jwt");
            assertThat(result.idTokenJwt()).isEqualTo("id-jwt");
            assertThat(result.scope()).isEqualTo("openid learcredential");
            assertThat(result.subject()).isEqualTo("did:key:z6MkSubject");
            assertThat(result.issueTime()).isNotNull();
            assertThat(result.expirationTime()).isAfter(result.issueTime());

            verify(jwtService, times(2)).generateJWT(anyString());
        }

        @Test
        @DisplayName("generates only access token for client_credentials grant")
        void generatesOnlyAccessToken() {
            ObjectNode credential = buildW3cCredential("LEARCredentialMachine");
            ExtractedClaims claims = ExtractedClaims.builder()
                    .subjectDid("did:key:z6MkMachine")
                    .scope("machine")
                    .idTokenClaims(Map.of())
                    .build();

            when(claimsExtractor.supports("LEARCredentialMachine")).thenReturn(true);
            when(claimsExtractor.extract(credential)).thenReturn(claims);
            when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
            when(jwtService.generateJWT(anyString())).thenReturn("access-jwt-only");

            TokenGenerationWorkflow.Result result = workflow.execute(credential, "https://verifier.example.com", Map.of(), false);

            assertThat(result.accessTokenJwt()).isEqualTo("access-jwt-only");
            assertThat(result.idTokenJwt()).isNull();

            verify(jwtService, times(1)).generateJWT(anyString());
        }

        @Test
        @DisplayName("throws when no ClaimsExtractor supports the credential type")
        void throwsWhenNoExtractorFound() {
            ObjectNode credential = buildW3cCredential("UnknownCredential");
            when(claimsExtractor.supports("UnknownCredential")).thenReturn(false);

            assertThatThrownBy(() -> workflow.execute(credential, "aud", Map.of(), false))
                    .isInstanceOf(OAuth2AuthenticationException.class);
        }
    }
}
