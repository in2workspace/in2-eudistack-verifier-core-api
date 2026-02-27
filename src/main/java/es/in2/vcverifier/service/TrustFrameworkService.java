package es.in2.vcverifier.service;

import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;

import java.util.List;

public interface TrustFrameworkService {
    List<IssuerCredentialsCapabilities> getTrustedIssuerListData(String id);
    boolean isCredentialRevokedInBitstringStatusList(String statusListCredentialUrl, String statusListIndex, String credentialStatusPurpose);
}
