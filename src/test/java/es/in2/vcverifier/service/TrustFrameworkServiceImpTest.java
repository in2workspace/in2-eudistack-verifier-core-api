package es.in2.vcverifier.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.exception.CredentialException;
import es.in2.vcverifier.exception.FailedCommunicationException;
import es.in2.vcverifier.model.StatusListCredentialData;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.service.impl.TrustFrameworkServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TrustFrameworkServiceImpTest {

    @InjectMocks
    private TrustFrameworkServiceImpl trustFrameworkService;

    @Mock
    private CertificateValidationService certificateValidationService;

    @Mock
    private StatusListCredentialService statusListCredentialService;

    @Mock
    private HttpClient httpClient;

    @Mock
    private TrustedIssuersProvider trustedIssuersProvider;

    // --- getTrustedIssuerListData ---

    @Test
    void shouldReturnListOfIssuerCredentialsCapabilities_whenProviderReturnsData() {
        String id = "issuer-id";
        List<IssuerCredentialsCapabilities> expectedCapabilities = List.of(
                IssuerCredentialsCapabilities.builder()
                        .credentialsType("SomeType")
                        .build()
        );
        when(trustedIssuersProvider.getIssuerCapabilities(id)).thenReturn(expectedCapabilities);

        List<IssuerCredentialsCapabilities> result = trustFrameworkService.getTrustedIssuerListData(id);

        assertEquals(1, result.size());
        assertEquals("SomeType", result.get(0).credentialsType());
        verify(trustedIssuersProvider).getIssuerCapabilities(id);
    }

    @Test
    void shouldReturnEmptyList_whenProviderReturnsEmpty() {
        when(trustedIssuersProvider.getIssuerCapabilities("unknown")).thenReturn(List.of());

        List<IssuerCredentialsCapabilities> result = trustFrameworkService.getTrustedIssuerListData("unknown");

        assertTrue(result.isEmpty());
    }

    // --- isCredentialRevokedInBitstringStatusList: input validation ---

    @Test
    void isCredentialRevoked_invalidStatusListIndex_throwsCredentialException() {
        assertThrows(CredentialException.class,
                () -> trustFrameworkService.isCredentialRevokedInBitstringStatusList(
                        "https://example.com/status", "not-a-number", "revocation"));
    }

    @Test
    void isCredentialRevoked_negativeIndex_throwsCredentialException() {
        assertThrows(CredentialException.class,
                () -> trustFrameworkService.isCredentialRevokedInBitstringStatusList(
                        "https://example.com/status", "-1", "revocation"));
    }

    // --- isCredentialRevokedInBitstringStatusList: HTTP failures ---

    @Test
    @SuppressWarnings("unchecked")
    void isCredentialRevoked_httpReturns404_throwsFailedCommunication() throws Exception {
        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(404);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThrows(FailedCommunicationException.class,
                () -> trustFrameworkService.isCredentialRevokedInBitstringStatusList(
                        "https://example.com/status", "0", "revocation"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void isCredentialRevoked_httpReturns500_throwsFailedCommunication() throws Exception {
        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(500);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThrows(FailedCommunicationException.class,
                () -> trustFrameworkService.isCredentialRevokedInBitstringStatusList(
                        "https://example.com/status", "0", "revocation"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void isCredentialRevoked_httpThrowsIOException_throwsFailedCommunication() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("connection refused"));

        assertThrows(FailedCommunicationException.class,
                () -> trustFrameworkService.isCredentialRevokedInBitstringStatusList(
                        "https://example.com/status", "0", "revocation"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void isCredentialRevoked_httpThrowsInterruptedException_throwsFailedCommunication() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new InterruptedException("interrupted"));

        assertThrows(FailedCommunicationException.class,
                () -> trustFrameworkService.isCredentialRevokedInBitstringStatusList(
                        "https://example.com/status", "0", "revocation"));
    }

    // --- isCredentialRevokedInBitstringStatusList: JWT parse failure ---

    @Test
    @SuppressWarnings("unchecked")
    void isCredentialRevoked_invalidJwt_throwsCredentialException() throws Exception {
        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn("not-a-jwt");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThrows(CredentialException.class,
                () -> trustFrameworkService.isCredentialRevokedInBitstringStatusList(
                        "https://example.com/status", "0", "revocation"));
    }

    // --- isCredentialRevokedInBitstringStatusList: index out of range ---

    @Test
    @SuppressWarnings("unchecked")
    void isCredentialRevoked_indexOutOfRange_throwsCredentialException() throws Exception {
        // Build a minimal valid-looking JWT string (header.payload.signature)
        String jwtString = buildMinimalJwtString("did:elsi:VATES-12345");

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(jwtString);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        // Certificate validation passes
        doNothing().when(certificateValidationService)
                .extractAndVerifyCertificate(any(), any(), any());

        byte[] rawBytes = new byte[]{(byte) 0xFF}; // 8 bits
        StatusListCredentialData statusData = new StatusListCredentialData(
                "did:elsi:VATES-12345", "revocation", rawBytes);

        when(statusListCredentialService.parse(any(SignedJWT.class))).thenReturn(statusData);
        doNothing().when(statusListCredentialService).validateStatusPurposeMatches(any(), any());
        when(statusListCredentialService.maxBits(any())).thenReturn(8);

        // Index 100 is out of range for 8-bit bitstring
        assertThrows(CredentialException.class,
                () -> trustFrameworkService.isCredentialRevokedInBitstringStatusList(
                        "https://example.com/status", "100", "revocation"));
    }

    // --- isCredentialRevokedInBitstringStatusList: happy path (revoked) ---

    @Test
    @SuppressWarnings("unchecked")
    void isCredentialRevoked_bitIsSet_returnsTrue() throws Exception {
        String jwtString = buildMinimalJwtString("did:elsi:VATES-12345");

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(jwtString);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        doNothing().when(certificateValidationService)
                .extractAndVerifyCertificate(any(), any(), any());

        byte[] rawBytes = new byte[]{(byte) 0xFF};
        StatusListCredentialData statusData = new StatusListCredentialData(
                "did:elsi:VATES-12345", "revocation", rawBytes);

        when(statusListCredentialService.parse(any(SignedJWT.class))).thenReturn(statusData);
        doNothing().when(statusListCredentialService).validateStatusPurposeMatches(any(), any());
        when(statusListCredentialService.maxBits(any())).thenReturn(8);
        when(statusListCredentialService.isBitSet(any(), eq(3))).thenReturn(true);

        boolean result = trustFrameworkService.isCredentialRevokedInBitstringStatusList(
                "https://example.com/status", "3", "revocation");

        assertTrue(result);
    }

    // --- isCredentialRevokedInBitstringStatusList: happy path (not revoked) ---

    @Test
    @SuppressWarnings("unchecked")
    void isCredentialRevoked_bitNotSet_returnsFalse() throws Exception {
        String jwtString = buildMinimalJwtString("did:elsi:VATES-12345");

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(jwtString);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        doNothing().when(certificateValidationService)
                .extractAndVerifyCertificate(any(), any(), any());

        byte[] rawBytes = new byte[]{0x00};
        StatusListCredentialData statusData = new StatusListCredentialData(
                "did:elsi:VATES-12345", "revocation", rawBytes);

        when(statusListCredentialService.parse(any(SignedJWT.class))).thenReturn(statusData);
        doNothing().when(statusListCredentialService).validateStatusPurposeMatches(any(), any());
        when(statusListCredentialService.maxBits(any())).thenReturn(8);
        when(statusListCredentialService.isBitSet(any(), eq(3))).thenReturn(false);

        boolean result = trustFrameworkService.isCredentialRevokedInBitstringStatusList(
                "https://example.com/status", "3", "revocation");

        assertFalse(result);
    }

    // --- isCredentialRevoked: missing issuer in JWT ---

    @Test
    @SuppressWarnings("unchecked")
    void isCredentialRevoked_missingIssuerClaim_throwsCredentialException() throws Exception {
        // JWT without "issuer" claim
        String jwtString = buildMinimalJwtString(null);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(jwtString);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThrows(CredentialException.class,
                () -> trustFrameworkService.isCredentialRevokedInBitstringStatusList(
                        "https://example.com/status", "0", "revocation"));
    }

    // --- isCredentialRevoked: non-did:elsi issuer ---

    @Test
    @SuppressWarnings("unchecked")
    void isCredentialRevoked_unsupportedIssuerDid_throwsCredentialException() throws Exception {
        String jwtString = buildMinimalJwtString("did:key:z123abc");

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(jwtString);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThrows(CredentialException.class,
                () -> trustFrameworkService.isCredentialRevokedInBitstringStatusList(
                        "https://example.com/status", "0", "revocation"));
    }

    // --- Helper: build a minimal unsigned JWT string for testing ---

    private String buildMinimalJwtString(String issuerDid) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .build();
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
            if (issuerDid != null) {
                claimsBuilder.claim("issuer", issuerDid);
            }
            // Create a JWSObject (unsigned) with a dummy signature for parsing
            JWSObject jwsObject = new JWSObject(header, new Payload(claimsBuilder.build().toJSONObject()));
            // We need a parseable JWT string - use base64url encoding manually
            String headerB64 = jwsObject.getHeader().toBase64URL().toString();
            String payloadB64 = jwsObject.getPayload().toBase64URL().toString();
            // Dummy signature (will fail verification but parses fine)
            String sigB64 = "dummysig";
            return headerB64 + "." + payloadB64 + "." + sigB64;
        } catch (Exception e) {
            throw new RuntimeException("Failed to build test JWT", e);
        }
    }
}
