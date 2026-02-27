package es.in2.vcverifier.verifier.infrastructure.adapter.clientregistry;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.verifier.domain.exception.RemoteFileFetchException;
import es.in2.vcverifier.verifier.domain.model.ExternalTrustedListYamlData;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Loads OIDC clients from a remote YAML file via HTTP.
 */
@Slf4j
@RequiredArgsConstructor
public class RemoteClientRegistryProvider implements ClientRegistryProvider {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final BackendConfig backendConfig;
    private final HttpClient httpClient;
    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());

    @Override
    public ExternalTrustedListYamlData loadClients() {
        String url = backendConfig.getClientsRepositoryUri();
        log.info("Fetching client registry from: {}", url);
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(REQUEST_TIMEOUT)
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                return yamlMapper.readValue(response.body(), ExternalTrustedListYamlData.class);
            } else {
                throw new RemoteFileFetchException("Failed to fetch clients YAML. Status code: " + response.statusCode());
            }
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RemoteFileFetchException("Error reading clients list from remote.", e);
        }
    }
}
