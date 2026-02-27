package es.in2.vcverifier.verifier.infrastructure.adapter.trustframework;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import es.in2.vcverifier.verifier.domain.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.verifier.domain.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.verifier.domain.service.TrustedIssuersProvider;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Resolves trusted issuer capabilities from a local YAML file.
 * Supports wildcard "*" to trust all issuers (useful for development).
 */
@Slf4j
public class LocalTrustedIssuersProvider implements TrustedIssuersProvider {

    private final Map<String, List<IssuerCredentialsCapabilities>> issuersMap;
    private final boolean trustAll;

    public LocalTrustedIssuersProvider() {
        this("local/trusted-issuers.yaml");
    }

    LocalTrustedIssuersProvider(String resourcePath) {
        ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(resourcePath)) {
            if (is == null) {
                log.warn("Local trusted issuers file not found: {}. Trusting all issuers.", resourcePath);
                this.issuersMap = Collections.emptyMap();
                this.trustAll = true;
                return;
            }
            TrustedIssuersYaml data = yamlMapper.readValue(is, TrustedIssuersYaml.class);
            if (data.trustedIssuers() != null && data.trustedIssuers().containsKey("*")) {
                log.info("Local trusted issuers: wildcard '*' — trusting all issuers");
                this.issuersMap = Collections.emptyMap();
                this.trustAll = true;
            } else {
                this.issuersMap = data.trustedIssuers() != null ? data.trustedIssuers() : Collections.emptyMap();
                this.trustAll = false;
                log.info("Loaded {} trusted issuers from local YAML", this.issuersMap.size());
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load local trusted issuers YAML", e);
        }
    }

    @Override
    public List<IssuerCredentialsCapabilities> getIssuerCapabilities(String issuerId) {
        if (trustAll) {
            log.debug("Trust-all mode: accepting issuer {}", issuerId);
            return List.of(
                    IssuerCredentialsCapabilities.builder()
                            .credentialsType("LEARCredentialEmployee")
                            .build(),
                    IssuerCredentialsCapabilities.builder()
                            .credentialsType("LEARCredentialMachine")
                            .build()
            );
        }

        List<IssuerCredentialsCapabilities> capabilities = issuersMap.get(issuerId);
        if (capabilities == null || capabilities.isEmpty()) {
            throw new IssuerNotAuthorizedException("Issuer with id: " + issuerId + " not found in local trusted issuers.");
        }
        return capabilities;
    }

    private record TrustedIssuersYaml(Map<String, List<IssuerCredentialsCapabilities>> trustedIssuers) {}
}
