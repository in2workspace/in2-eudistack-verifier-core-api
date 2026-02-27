package es.in2.vcverifier.verifier.domain.service;

import es.in2.vcverifier.verifier.domain.model.ExternalTrustedListYamlData;

/**
 * SPI for loading OIDC client registrations.
 * Implementations provide client data from different sources (remote YAML, local YAML, etc.).
 */
public interface ClientRegistryProvider {
    ExternalTrustedListYamlData loadClients();
}
