package es.in2.vcverifier.verifier.domain.service;

import es.in2.vcverifier.verifier.domain.model.issuer.IssuerCredentialsCapabilities;

import java.util.List;

public interface TrustFrameworkService {
    List<IssuerCredentialsCapabilities> getTrustedIssuerListData(String id);
    boolean isCredentialRevokedInBitstringStatusList(String statusListCredentialUrl, String statusListIndex, String credentialStatusPurpose);
}
