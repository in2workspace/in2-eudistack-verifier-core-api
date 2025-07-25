package es.in2.vcverifier.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.dto.CredentialStatusResponse;
import es.in2.vcverifier.service.impl.TrustFrameworkServiceImpl;
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
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TrustFrameworkServiceImpTest {

    @InjectMocks
    private TrustFrameworkServiceImpl trustFrameworkService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    HttpResponse<String> httpResponse;

    @Mock
    HttpClient mockClient;

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
}
