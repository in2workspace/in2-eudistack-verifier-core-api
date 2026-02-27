package es.in2.vcverifier.shared.config.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.NoSuchElementException;

@Validated
@ConfigurationProperties(prefix = "verifier.backend")
public record BackendProperties(
        @NotBlank @URL String url,
        Identity identity,
        @NotNull @Valid List<TrustFramework> trustFrameworks,
        LocalFiles localFiles
) {

    public record Identity(
            String didKey,
            String privateKey) {}

    public record TrustFramework(
            @NotBlank String name,
            String trustedIssuersListUrl,
            String trustedServicesListUrl
    ) {}

    /**
     * Optional external filesystem paths. When set, the corresponding local provider
     * reads from the filesystem instead of the classpath, allowing injection via
     * Docker volumes, Kubernetes ConfigMaps, etc.
     */
    public record LocalFiles(
            String clientsPath,
            String trustedIssuersPath,
            String schemasDir
    ) {}

    // TODO: this is temporary while VCVerifier can handle only one trustFramework
    public TrustFramework getDOMETrustFrameworkByName() {
        return trustFrameworks.stream()
                .filter(tf -> tf.name().equalsIgnoreCase("DOME"))
                .findFirst()
                .orElseThrow(() -> new NoSuchElementException("No TrustFramework found with name 'DOME'"));
    }
}
