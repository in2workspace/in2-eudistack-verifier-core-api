package es.in2.vcverifier.config;

import es.in2.vcverifier.config.properties.FrontendProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class FrontendConfig {

    private final FrontendProperties properties;

    public String getOnboardingUrl() {
        return properties.urls().onboarding();
    }

    public String getSupportUrl() {
        return properties.urls().support();
    }

    public String getWalletUrl() {
        return properties.urls().wallet();
    }

    public String getPrimaryColor() {
        return defaultIfBlank(properties.colors().primary(), "#2D58A7");
    }

    public String getPrimaryContrastColor() {
        return defaultIfBlank(properties.colors().primaryContrast(), "#ffffff");
    }

    public String getSecondaryColor() {
        return defaultIfBlank(properties.colors().secondary(), "#14274A");
    }

    public String getSecondaryContrastColor() {
        return defaultIfBlank(properties.colors().secondaryContrast(), "#00ADD3");
    }

    public String getLogoSrc() {
        return properties.logoSrc();
    }

    public String getFaviconSrc() {
        return defaultIfBlank(properties.faviconSrc(), "dome_logo_favicon.png");
    }

    private String defaultIfBlank(String value, String defaultValue) {
        return (value == null || value.trim().isEmpty()) ? defaultValue : value;
    }
}
