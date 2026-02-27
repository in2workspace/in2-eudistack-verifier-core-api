package es.in2.vcverifier.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.service.TrustedIssuersProvider;
import es.in2.vcverifier.service.impl.EbsiV4TrustedIssuersProvider;
import es.in2.vcverifier.service.impl.LocalTrustedIssuersProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.http.HttpClient;

@Slf4j
@Configuration
public class TrustedIssuersConfig {

    @Bean
    @ConditionalOnProperty(name = "verifier.backend.trustFrameworks[0].trustedIssuersListUrl")
    public TrustedIssuersProvider ebsiV4TrustedIssuersProvider(BackendConfig backendConfig, ObjectMapper objectMapper, HttpClient httpClient) {
        log.info("Using EBSI v4 Trusted Issuers Provider (remote)");
        return new EbsiV4TrustedIssuersProvider(backendConfig, objectMapper, httpClient);
    }

    @Bean
    @ConditionalOnMissingBean(TrustedIssuersProvider.class)
    public TrustedIssuersProvider localTrustedIssuersProvider() {
        log.info("Using Local Trusted Issuers Provider (YAML)");
        return new LocalTrustedIssuersProvider();
    }
}
