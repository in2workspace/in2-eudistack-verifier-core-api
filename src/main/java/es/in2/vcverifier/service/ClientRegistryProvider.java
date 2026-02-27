package es.in2.vcverifier.service;

import es.in2.vcverifier.model.ExternalTrustedListYamlData;

/**
 * SPI for loading OIDC client registrations.
 * Implementations provide client data from different sources (remote YAML, local YAML, etc.).
 */
public interface ClientRegistryProvider {
    ExternalTrustedListYamlData loadClients();
}
