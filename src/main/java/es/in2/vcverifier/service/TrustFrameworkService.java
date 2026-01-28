package es.in2.vcverifier.service;

import es.in2.vcverifier.model.ExternalTrustedListYamlData;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;

import java.util.List;

public interface TrustFrameworkService {
    List<IssuerCredentialsCapabilities> getTrustedIssuerListData(String id);
    List<String> getCredentialStatusListData(String url);
    List<String> getRevokedCredentialIds();
    ExternalTrustedListYamlData fetchAllowedClient();
    boolean isCredentialRevokedInBitstringStatusList(String statusListCredentialUrl, String statusListIndex, String credentialStatusPurpose);
}
