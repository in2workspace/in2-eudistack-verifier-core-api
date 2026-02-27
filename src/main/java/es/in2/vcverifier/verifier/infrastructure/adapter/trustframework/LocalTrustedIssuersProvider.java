package es.in2.vcverifier.verifier.infrastructure.adapter.trustframework;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import es.in2.vcverifier.verifier.domain.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.verifier.domain.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.verifier.domain.service.TrustedIssuersProvider;
import lombok.extern.slf4j.Slf4j;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Resolves trusted issuer capabilities from a local YAML file.
 * If an external filesystem path is configured, reads from there;
 * otherwise falls back to the classpath resource.
 * Supports wildcard "*" to trust all issuers (useful for development).
 */
@Slf4j
public class LocalTrustedIssuersProvider implements TrustedIssuersProvider {

    private static final String CLASSPATH_RESOURCE = "local/trusted-issuers.yaml";
    private final Map<String, List<IssuerCredentialsCapabilities>> issuersMap;
    private final boolean trustAll;

    public LocalTrustedIssuersProvider() {
        this(null);
    }

    public LocalTrustedIssuersProvider(String externalPath) {
        ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
        try (InputStream is = openInputStream(externalPath)) {
            if (is == null) {
                log.warn("Local trusted issuers file not found. Trusting all issuers.");
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

    private InputStream openInputStream(String externalPath) throws IOException {
        if (externalPath != null && !externalPath.isBlank()) {
            Path path = Path.of(externalPath);
            if (Files.exists(path)) {
                log.info("Loading trusted issuers from external file: {}", externalPath);
                return new FileInputStream(path.toFile());
            }
            log.warn("External trusted issuers file not found: {}. Falling back to classpath.", externalPath);
        }
        log.info("Loading trusted issuers from classpath: {}", CLASSPATH_RESOURCE);
        return getClass().getClassLoader().getResourceAsStream(CLASSPATH_RESOURCE);
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
