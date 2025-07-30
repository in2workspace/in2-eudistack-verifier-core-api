package es.in2.vcverifier.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.config.BackendConfig;
import es.in2.vcverifier.dto.CredentialStatusResponse;
import es.in2.vcverifier.model.ExternalTrustedListYamlData;
import es.in2.vcverifier.model.issuer.IssuerAttribute;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.model.issuer.IssuerResponse;
import es.in2.vcverifier.service.impl.TrustFrameworkServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TrustFrameworkServiceImpTest {

    @InjectMocks
    private TrustFrameworkServiceImpl trustFrameworkService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private BackendConfig backendConfig;

    @Mock
    HttpResponse<String> httpResponse;

    @Mock
    HttpClient mockClient;

    @BeforeEach
    void mockreset(){
        reset(objectMapper);
    }

    @Test
    void shouldReturnListOfNonces_whenStatusCodeIs200() throws Exception {
        // Given
        String url = "https://example.com/credential-status";
        String responseBody = "[{\"nonce\": \"abc\"}, {\"nonce\": \"def\"}]";

        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn(responseBody);

        // Simular cliente HTTP estático
        try (MockedStatic<HttpClient> mockedHttpClient = mockStatic(HttpClient.class)) {
            mockedHttpClient.when(HttpClient::newHttpClient).thenReturn(mockClient);
            when(mockClient.send(any(), eq(HttpResponse.BodyHandlers.ofString()))).thenReturn(httpResponse);

            List<CredentialStatusResponse> mockList = List.of(
                    new CredentialStatusResponse("abc"),
                    new CredentialStatusResponse("def")
            );
            when(objectMapper.readValue(eq(responseBody), ArgumentMatchers.<TypeReference<List<CredentialStatusResponse>>>any())).thenReturn(mockList);

            // When
            List<String> result = trustFrameworkService.getCredentialStatusListData(url);

            // Then
            assertEquals(List.of("abc", "def"), result);
        }
    }

    @Test
    void shouldReturnListOfIssuerCredentialsCapabilities_whenStatusCodeIs200() throws Exception {
        // Given
        String id = "issuer-id";
        String responseBody = "[{\"nonce\": \"abc\"}, {\"nonce\": \"def\"}]";
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn(responseBody);
        when(backendConfig.getTrustedIssuerListUri()).thenReturn("https://test.com/clients.yaml");

        try (MockedStatic<HttpClient> mockedHttpClient = mockStatic(HttpClient.class)) {
            mockedHttpClient.when(HttpClient::newHttpClient).thenReturn(mockClient);
            when(mockClient.send(any(), eq(HttpResponse.BodyHandlers.ofString()))).thenReturn(httpResponse);

            IssuerAttribute attribute = IssuerAttribute.builder()
                    .body("eyJ0eXBlIjoiU29tZVR5cGUifQ==")
                    .hash("hash1")
                    .issuerType("type1")
                    .build();

            IssuerResponse issuerResponse = IssuerResponse.builder()
                    .did("did:example:123")
                    .attributes(List.of(attribute))
                    .build();

            IssuerCredentialsCapabilities expectedCapability = IssuerCredentialsCapabilities.builder()
                    .credentialsType("SomeType")
                    .build();

            when(objectMapper.readValue(eq(responseBody), eq(IssuerResponse.class))).thenReturn(issuerResponse);
            when(objectMapper.readValue(eq("{\"type\":\"SomeType\"}"), eq(IssuerCredentialsCapabilities.class)))
                    .thenReturn(expectedCapability);

            // When
            List<IssuerCredentialsCapabilities> result = trustFrameworkService.getTrustedIssuerListData(id);

            // Then
            assertEquals(1, result.size());
            assertEquals("SomeType", result.get(0).credentialsType());
        }
    }


    @Test
    void shouldReturnListOfRevokedCredentialIds_whenYamlIsValid() throws Exception {
        // Given
        String yamlResponse =  "revoked_credentials:\n  - id1\n  - id2";
        when(backendConfig.getRevocationListUri()).thenReturn("https://test.com/clients.yaml");

        try (MockedStatic<HttpClient> mockedHttpClient = mockStatic(HttpClient.class)) {
            mockedHttpClient.when(HttpClient::newHttpClient).thenReturn(mockClient);
            when(httpResponse.statusCode()).thenReturn(200);
            when(httpResponse.body()).thenReturn(yamlResponse);
            when(mockClient.send(any(), eq(HttpResponse.BodyHandlers.ofString()))).thenReturn(httpResponse);

            // When
            List<String> result = trustFrameworkService.getRevokedCredentialIds();

            // Then
            assertEquals(List.of("id1", "id2"), result);
        }
    }

    @Test
    void shouldReturnExternalTrustedList_whenYamlFetchedSuccessfully() throws Exception {
        // Given
        String yamlResponse = "clients: []";
        ExternalTrustedListYamlData mockTrustedList = new ExternalTrustedListYamlData(List.of());
        when(backendConfig.getClientsRepositoryUri()).thenReturn("https://test.com/clients.yaml");

        try (MockedStatic<HttpClient> mockedHttpClient = mockStatic(HttpClient.class)) {
            mockedHttpClient.when(HttpClient::newHttpClient).thenReturn(mockClient);
            when(httpResponse.statusCode()).thenReturn(200);
            when(httpResponse.body()).thenReturn(yamlResponse);
            when(mockClient.send(any(), eq(HttpResponse.BodyHandlers.ofString()))).thenReturn(httpResponse);

            // When
            ExternalTrustedListYamlData result = trustFrameworkService.fetchAllowedClient();

            // Then
            assertEquals(mockTrustedList, result);
        }
    }



}
