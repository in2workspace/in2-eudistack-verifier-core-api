package es.in2.vcverifier.verifier.infrastructure.adapter.trustframework;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.config.BackendConfig;
import es.in2.vcverifier.shared.domain.exception.FailedCommunicationException;
import es.in2.vcverifier.verifier.domain.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.shared.domain.exception.JsonConversionException;
import es.in2.vcverifier.verifier.domain.model.issuer.IssuerAttribute;
import es.in2.vcverifier.verifier.domain.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.verifier.domain.model.issuer.IssuerResponse;
import es.in2.vcverifier.verifier.domain.service.TrustedIssuersProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;

/**
 * Resolves trusted issuer capabilities from an EBSI v4 Trusted Issuers Registry.
 */
@Slf4j
@RequiredArgsConstructor
public class EbsiV4TrustedIssuersProvider implements TrustedIssuersProvider {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final BackendConfig backendConfig;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;

    @Override
    public List<IssuerCredentialsCapabilities> getIssuerCapabilities(String issuerId) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(backendConfig.getTrustedIssuerListUri() + issuerId))
                    .timeout(REQUEST_TIMEOUT)
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                IssuerResponse issuerResponse = objectMapper.readValue(response.body(), IssuerResponse.class);
                return issuerResponse.attributes().stream()
                        .map(this::decodeAndMapIssuerAttributeBody)
                        .toList();
            } else if (response.statusCode() == 404) {
                throw new IssuerNotAuthorizedException("Issuer with id: " + issuerId + " not found.");
            } else {
                throw new IOException("Failed to fetch issuer data. Status code: " + response.statusCode());
            }
        } catch (IssuerNotAuthorizedException e) {
            log.error("Issuer not found: {}", e.getMessage());
            throw e;
        } catch (IOException | InterruptedException e) {
            log.error("Error fetching issuer data for id {}: {}", issuerId, e.getMessage());
            Thread.currentThread().interrupt();
            throw new FailedCommunicationException("Error fetching issuer data");
        }
    }

    private IssuerCredentialsCapabilities decodeAndMapIssuerAttributeBody(IssuerAttribute issuerAttribute) {
        try {
            String decodedBody = new String(Base64.getDecoder().decode(issuerAttribute.body()), StandardCharsets.UTF_8);
            return objectMapper.readValue(decodedBody, IssuerCredentialsCapabilities.class);
        } catch (IOException e) {
            log.error("Failed to decode and map issuer attribute body: {}", e.getMessage());
            throw new JsonConversionException("Failed to decode and map issuer attribute body");
        }
    }
}
