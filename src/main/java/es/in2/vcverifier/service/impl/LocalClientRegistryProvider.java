package es.in2.vcverifier.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import es.in2.vcverifier.model.ExternalTrustedListYamlData;
import es.in2.vcverifier.service.ClientRegistryProvider;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;

/**
 * Loads OIDC clients from a local YAML file on the classpath.
 */
@Slf4j
public class LocalClientRegistryProvider implements ClientRegistryProvider {

    private static final String LOCAL_CLIENTS_PATH = "local/clients.yaml";
    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());

    @Override
    public ExternalTrustedListYamlData loadClients() {
        log.info("Loading client registry from local YAML: {}", LOCAL_CLIENTS_PATH);
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(LOCAL_CLIENTS_PATH)) {
            if (is == null) {
                throw new IllegalStateException("Local clients file not found on classpath: " + LOCAL_CLIENTS_PATH);
            }
            return yamlMapper.readValue(is, ExternalTrustedListYamlData.class);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read local clients YAML", e);
        }
    }
}
