package es.in2.vcverifier.shared.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "verifier.frontend")
public record FrontendProperties(
        @NestedConfigurationProperty Urls urls,
        @NestedConfigurationProperty Colors colors,
        @NestedConfigurationProperty Assets assets,
        String defaultLang
) {

    public record Urls(
            String onboarding,
            String support,
            String wallet
    ) {}

    public record Colors(
            String primary,
            String primaryContrast,
            String secondary,
            String secondaryContrast
    ) {}

    public record Assets(
            String baseUrl,
            String logoPath,
            String faviconPath
    ) {}
}
