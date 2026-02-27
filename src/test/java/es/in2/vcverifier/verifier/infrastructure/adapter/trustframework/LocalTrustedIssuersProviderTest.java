package es.in2.vcverifier.verifier.infrastructure.adapter.trustframework;

import es.in2.vcverifier.verifier.domain.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.verifier.domain.model.issuer.IssuerCredentialsCapabilities;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LocalTrustedIssuersProviderTest {

    @Test
    void wildcard_trustsAllIssuers() {
        // The default local/trusted-issuers.yaml uses wildcard "*"
        LocalTrustedIssuersProvider provider = new LocalTrustedIssuersProvider();

        List<IssuerCredentialsCapabilities> capabilities = provider.getIssuerCapabilities("did:elsi:VATES-99999999");

        assertNotNull(capabilities);
        assertFalse(capabilities.isEmpty());
        assertTrue(capabilities.stream().anyMatch(c -> "LEARCredentialEmployee".equals(c.credentialsType())));
        assertTrue(capabilities.stream().anyMatch(c -> "LEARCredentialMachine".equals(c.credentialsType())));
    }

    @Test
    void missingFile_defaultsToTrustAll() {
        LocalTrustedIssuersProvider provider = new LocalTrustedIssuersProvider("/nonexistent/file.yaml");

        List<IssuerCredentialsCapabilities> capabilities = provider.getIssuerCapabilities("did:elsi:ANY");

        assertNotNull(capabilities);
        assertFalse(capabilities.isEmpty());
    }

    @Test
    void specificIssuers_returnsCapabilities() {
        String path = resolveTestFixture("test-fixtures/specific-issuers.yaml");
        LocalTrustedIssuersProvider provider = new LocalTrustedIssuersProvider(path);

        List<IssuerCredentialsCapabilities> capabilities = provider.getIssuerCapabilities("did:elsi:VATES-12345678");

        assertNotNull(capabilities);
        assertEquals(1, capabilities.size());
        assertEquals("LEARCredentialEmployee", capabilities.get(0).credentialsType());
    }

    @Test
    void specificIssuers_unknownIssuer_throwsException() {
        String path = resolveTestFixture("test-fixtures/specific-issuers.yaml");
        LocalTrustedIssuersProvider provider = new LocalTrustedIssuersProvider(path);

        assertThrows(IssuerNotAuthorizedException.class,
                () -> provider.getIssuerCapabilities("did:elsi:UNKNOWN"));
    }

    private static String resolveTestFixture(String classpathResource) {
        URL url = LocalTrustedIssuersProviderTest.class.getClassLoader().getResource(classpathResource);
        assertNotNull(url, "Test fixture not found on classpath: " + classpathResource);
        return url.getPath();
    }
}
