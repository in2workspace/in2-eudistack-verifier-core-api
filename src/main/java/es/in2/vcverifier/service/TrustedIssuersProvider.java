package es.in2.vcverifier.service;

import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;

import java.util.List;

/**
 * SPI for resolving trusted issuer capabilities.
 * Implementations provide issuer data from different sources (EBSI, local YAML, etc.).
 */
public interface TrustedIssuersProvider {
    List<IssuerCredentialsCapabilities> getIssuerCapabilities(String issuerId);
}
