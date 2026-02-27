package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.FrontendProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class FrontendConfig {

    private final FrontendProperties properties;

    public String getPortalUrl() {
        return properties.portalUrl();
    }
}
