package es.in2.vcverifier.config.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "verifier.frontend")
public record FrontendProperties(
        @NotNull @NestedConfigurationProperty Urls urls,
        @NestedConfigurationProperty Colors colors,
        @NotBlank String logoSrc,
        String faviconSrc,
        String defaultLang) {

    public record Urls(
            @NotBlank @URL String onboarding,
            @NotBlank @URL String support,
            @NotBlank @URL String wallet) {}

    public record Colors(
            String primary,
            String primaryContrast,
            String secondary,
            String secondaryContrast
    ) {}
}
