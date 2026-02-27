package es.in2.vcverifier.verifier.infrastructure.config;

import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.verifier.infrastructure.adapter.clientregistry.LocalClientRegistryProvider;
import es.in2.vcverifier.verifier.infrastructure.adapter.clientregistry.RemoteClientRegistryProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.http.HttpClient;

@Slf4j
@Configuration
public class ClientRegistryConfig {

    @Bean
    @ConditionalOnProperty(name = "verifier.backend.trustFrameworks[0].trustedServicesListUrl")
    public ClientRegistryProvider remoteClientRegistryProvider(BackendConfig backendConfig, HttpClient httpClient) {
        log.info("Using Remote Client Registry Provider");
        return new RemoteClientRegistryProvider(backendConfig, httpClient);
    }

    @Bean
    @ConditionalOnMissingBean(ClientRegistryProvider.class)
    public ClientRegistryProvider localClientRegistryProvider(BackendConfig backendConfig) {
        log.info("Using Local Client Registry Provider (YAML)");
        return new LocalClientRegistryProvider(backendConfig.getLocalClientsPath());
    }
}
