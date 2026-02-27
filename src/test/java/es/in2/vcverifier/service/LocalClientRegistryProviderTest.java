package es.in2.vcverifier.service;

import es.in2.vcverifier.model.ExternalTrustedListYamlData;
import es.in2.vcverifier.service.impl.LocalClientRegistryProvider;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LocalClientRegistryProviderTest {

    @Test
    void loadClients_fromDefaultLocalYaml_success() {
        LocalClientRegistryProvider provider = new LocalClientRegistryProvider();

        ExternalTrustedListYamlData data = provider.loadClients();

        assertNotNull(data);
        assertNotNull(data.clients());
        assertFalse(data.clients().isEmpty());
        assertEquals("dev-client", data.clients().get(0).clientId());
    }

    @Test
    void loadClients_containsExpectedDevClient() {
        LocalClientRegistryProvider provider = new LocalClientRegistryProvider();

        ExternalTrustedListYamlData data = provider.loadClients();

        var client = data.clients().get(0);
        assertEquals("dev-client", client.clientId());
        assertTrue(client.redirectUris().contains("http://localhost:4200/callback"));
        assertTrue(client.scopes().contains("openid"));
    }
}
