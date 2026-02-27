package es.in2.vcverifier.service.impl;

import es.in2.vcverifier.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.service.impl.LocalTrustedIssuersProvider;
import org.junit.jupiter.api.Test;

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
        LocalTrustedIssuersProvider provider = new LocalTrustedIssuersProvider("nonexistent/file.yaml");

        List<IssuerCredentialsCapabilities> capabilities = provider.getIssuerCapabilities("did:elsi:ANY");

        assertNotNull(capabilities);
        assertFalse(capabilities.isEmpty());
    }

    @Test
    void specificIssuers_returnsCapabilities() {
        // Use test resource with specific issuers
        LocalTrustedIssuersProvider provider = new LocalTrustedIssuersProvider("test-fixtures/specific-issuers.yaml");

        List<IssuerCredentialsCapabilities> capabilities = provider.getIssuerCapabilities("did:elsi:VATES-12345678");

        assertNotNull(capabilities);
        assertEquals(1, capabilities.size());
        assertEquals("LEARCredentialEmployee", capabilities.get(0).credentialsType());
    }

    @Test
    void specificIssuers_unknownIssuer_throwsException() {
        LocalTrustedIssuersProvider provider = new LocalTrustedIssuersProvider("test-fixtures/specific-issuers.yaml");

        assertThrows(IssuerNotAuthorizedException.class,
                () -> provider.getIssuerCapabilities("did:elsi:UNKNOWN"));
    }
}
