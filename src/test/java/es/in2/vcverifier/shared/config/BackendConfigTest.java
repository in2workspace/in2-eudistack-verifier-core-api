package es.in2.vcverifier.shared.config;
import es.in2.vcverifier.shared.config.BackendConfig;

import es.in2.vcverifier.shared.config.properties.BackendProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ContextConfiguration;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {BackendConfig.class, BackendConfigTest.TestConfig.class})
@ActiveProfiles("test")
@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class)
class BackendConfigTest {

    @Autowired
    private BackendConfig backendConfig;

    @Test
    void testBackendConfig() {
        assertThat(backendConfig.getUrl())
                .as("Backend URL should match")
                .isEqualTo("https://raw.githubusercontent.com");

     assertThat(backendConfig.getPrivateKey())
        .as("Private key should remove 0x prefix")
        .isEqualTo("73e509a7681d4a395b1ced75681c4dc4020dbab02da868512276dd766733d5b5");

        assertThat(backendConfig.getTrustedIssuerListUri())
                .as("Trusted Issuer List URL should match")
                .isEqualTo("https://raw.githubusercontent.com");

        assertThat(backendConfig.getClientsRepositoryUri())
                .as("Clients Repository URI should match")
                .isEqualTo("https://raw.githubusercontent.com/in2workspace/in2-dome-gitops/refs/heads/main/trust-framework/trusted_services_list.yaml");
    }

    @Configuration
    @EnableConfigurationProperties(BackendProperties.class)
    static class TestConfig {
    }
}
