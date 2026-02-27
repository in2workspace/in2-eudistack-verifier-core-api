package es.in2.vcverifier.verifier.infrastructure.adapter.clientregistry;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import es.in2.vcverifier.verifier.domain.model.ExternalTrustedListYamlData;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import lombok.extern.slf4j.Slf4j;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Loads OIDC clients from a local YAML file.
 * If an external filesystem path is configured, reads from there;
 * otherwise falls back to the classpath resource.
 */
@Slf4j
public class LocalClientRegistryProvider implements ClientRegistryProvider {

    private static final String CLASSPATH_CLIENTS_PATH = "local/clients.yaml";
    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
    private final String externalPath;

    public LocalClientRegistryProvider() {
        this(null);
    }

    public LocalClientRegistryProvider(String externalPath) {
        this.externalPath = externalPath;
    }

    @Override
    public ExternalTrustedListYamlData loadClients() {
        try (InputStream is = openInputStream()) {
            return yamlMapper.readValue(is, ExternalTrustedListYamlData.class);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read local clients YAML", e);
        }
    }

    private InputStream openInputStream() throws IOException {
        if (externalPath != null && !externalPath.isBlank()) {
            Path path = Path.of(externalPath);
            if (Files.exists(path)) {
                log.info("Loading client registry from external file: {}", externalPath);
                return new FileInputStream(path.toFile());
            }
            log.warn("External clients file not found: {}. Falling back to classpath.", externalPath);
        }
        log.info("Loading client registry from classpath: {}", CLASSPATH_CLIENTS_PATH);
        InputStream is = getClass().getClassLoader().getResourceAsStream(CLASSPATH_CLIENTS_PATH);
        if (is == null) {
            throw new IllegalStateException("Local clients file not found on classpath: " + CLASSPATH_CLIENTS_PATH);
        }
        return is;
    }
}
