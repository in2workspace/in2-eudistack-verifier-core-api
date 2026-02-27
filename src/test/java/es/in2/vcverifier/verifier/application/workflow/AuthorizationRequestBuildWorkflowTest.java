package es.in2.vcverifier.verifier.application.workflow;

import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationRequestJWT;
import es.in2.vcverifier.shared.crypto.CryptoComponent;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.verifier.domain.exception.InvalidScopeException;
import com.nimbusds.jose.jwk.ECKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorizationRequestBuildWorkflowTest {

    @Mock private JWTService jwtService;
    @Mock private CryptoComponent cryptoComponent;
    @Mock private BackendConfig backendConfig;
    @Mock private CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;
    @Mock private CacheStore<String> cacheForNonceByState;
    @Mock private ECKey ecKey;

    private AuthorizationRequestBuildWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new AuthorizationRequestBuildWorkflow(
                jwtService, cryptoComponent, backendConfig,
                cacheStoreForAuthorizationRequestJWT, cacheForNonceByState
        );
    }

    @Test
    @DisplayName("execute() builds JWT, generates openid4vp URL, and caches the result")
    void execute_buildsJwtAndGeneratesUrl() {
        when(cryptoComponent.getECKey()).thenReturn(ecKey);
        when(ecKey.getKeyID()).thenReturn("did:key:z6Mk...");
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
        when(jwtService.generateJWTwithOI4VPType(anyString())).thenReturn("signed-jwt-content");

        AuthorizationRequestBuildWorkflow.Result result = workflow.execute("My Client", "openid learcredential", "state-123");

        assertThat(result.signedAuthRequestJwt()).isEqualTo("signed-jwt-content");
        assertThat(result.openid4vpUrl()).startsWith("openid4vp://");
        assertThat(result.openid4vpUrl()).contains("client_id=");
        assertThat(result.openid4vpUrl()).contains("request_uri=");
        assertThat(result.nonce()).isNotBlank();
        assertThat(result.homeUri()).isEqualTo("My Client");

        // Verify JWT was cached
        verify(cacheStoreForAuthorizationRequestJWT).add(eq(result.nonce()), any(AuthorizationRequestJWT.class));
        // Verify nonce-by-state was cached
        verify(cacheForNonceByState).add(eq("state-123"), anyString());
    }

    @Test
    @DisplayName("execute() throws InvalidScopeException when scope lacks 'learcredential'")
    void execute_throwsOnInvalidScope() {
        assertThatThrownBy(() -> workflow.execute("Client", "openid email", "state-1"))
                .isInstanceOf(InvalidScopeException.class)
                .hasMessageContaining("learcredential");
    }

    @Test
    @DisplayName("execute() passes the correct payload structure to JWTService")
    void execute_passesCorrectPayload() {
        when(cryptoComponent.getECKey()).thenReturn(ecKey);
        when(ecKey.getKeyID()).thenReturn("did:key:testkey");
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
        when(jwtService.generateJWTwithOI4VPType(anyString())).thenReturn("signed");

        workflow.execute("Client", "openid learcredential", "my-state");

        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(jwtService).generateJWTwithOI4VPType(payloadCaptor.capture());

        String payload = payloadCaptor.getValue();
        assertThat(payload).contains("did:key:testkey");
        assertThat(payload).contains("response_uri");
        assertThat(payload).contains("dcql_query");
        assertThat(payload).contains("vp_token");
        assertThat(payload).contains("my-state");
    }
}
