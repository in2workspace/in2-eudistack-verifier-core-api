package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.BackendProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class BackendConfig {

    private final BackendProperties properties;

    public String getUrl() {
        return properties.url();
    }

    public String getPrivateKey() {
        String privateKey = properties.identity() != null ? properties.identity().privateKey() : null;
        if (privateKey != null && privateKey.startsWith("0x")) {
            privateKey = privateKey.substring(2);
        }
        return privateKey;
    }

    public String getDidKey() {
        return properties.identity() != null ? properties.identity().didKey() : null;
    }

    public boolean hasIdentityConfigured() {
        return properties.identity() != null
                && properties.identity().privateKey() != null
                && !properties.identity().privateKey().isBlank();
    }

    private BackendProperties.TrustFramework getSelectedTrustFramework() {
        return properties.getDOMETrustFrameworkByName();
    }

    public String getTrustedIssuerListUri() {
        return getSelectedTrustFramework().trustedIssuersListUrl();
    }

    public String getClientsRepositoryUri() {
        return getSelectedTrustFramework().trustedServicesListUrl();
    }

    // todo currently unused, will be used when Verifier can manage multiple trustframeworks
    public List<BackendProperties.TrustFramework> getAllTrustFrameworks() {
        return properties.trustFrameworks();
    }

    public String getLocalClientsPath() {
        return properties.localFiles() != null ? properties.localFiles().clientsPath() : null;
    }

    public String getLocalTrustedIssuersPath() {
        return properties.localFiles() != null ? properties.localFiles().trustedIssuersPath() : null;
    }

    public String getLocalSchemasDir() {
        return properties.localFiles() != null ? properties.localFiles().schemasDir() : null;
    }
}
