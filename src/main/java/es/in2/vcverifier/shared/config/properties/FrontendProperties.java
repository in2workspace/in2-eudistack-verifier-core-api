package es.in2.vcverifier.shared.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "verifier.frontend")
public record FrontendProperties(
        String portalUrl
) {
}
