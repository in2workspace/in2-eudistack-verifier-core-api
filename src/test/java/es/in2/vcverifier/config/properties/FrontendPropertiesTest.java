package es.in2.vcverifier.config.properties;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = FrontendPropertiesTest.TestConfig.class)
@ActiveProfiles("test")
@ConfigurationPropertiesScan("es.in2.vcverifier.config.properties")
class FrontendPropertiesTest {

    @Autowired
    private FrontendProperties frontendProperties;

    @Test
    void testFrontendProperties() {
        FrontendProperties.Urls expectedUrls = new FrontendProperties.Urls(
                "https://example.com/onboarding",
                "https://example.com/support",
                "https://example.com/wallet"
        );

        FrontendProperties.Colors expectedColors = new FrontendProperties.Colors(
                "#FF0000",
                "#FFFFFF",
                "#00ADD3",
                "#000000"
        );

        FrontendProperties.Images expectedImages = new FrontendProperties.Images(
                "https://cdn.jsdelivr.net/gh/in2workspace/eudistack-images@main/Altia",
                "altia-logo.png",
                "altia-favicon.ico"
        );

        assertThat(frontendProperties.urls())
                .as("URLs should match the provided values")
                .isEqualTo(expectedUrls);

        assertThat(frontendProperties.colors())
                .as("Colors should match the provided values")
                .isEqualTo(expectedColors);

        assertThat(frontendProperties.images())
                .as("Images should match the provided values")
                .isEqualTo(expectedImages);

        assertThat(frontendProperties.defaultLang())
                .as("Default lang should be en")
                .isEqualTo("en");
    }

    @EnableConfigurationProperties(FrontendProperties.class)
    static class TestConfig {
    }

    @Test
    void testMissingMandatoryOnboardingUrlCausesError() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "verifier.frontend.urls.support=https://example.com/support",
                        "verifier.frontend.urls.wallet=https://example.com/wallet",
                        "verifier.frontend.images.baseUrl=https://cdn.example.com/assets",
                        "verifier.frontend.images.logoPath=logo.png"
                )
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void testMissingMandatorySupportUrlCausesError() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "verifier.frontend.urls.onboarding=https://example.com/onboarding",
                        "verifier.frontend.urls.wallet=https://example.com/wallet",
                        "verifier.frontend.images.baseUrl=https://cdn.example.com/assets",
                        "verifier.frontend.images.logoPath=logo.png"
                )
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void testMissingMandatoryWalletUrlCausesError() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "verifier.frontend.urls.onboarding=https://example.com/onboarding",
                        "verifier.frontend.urls.support=https://example.com/support",
                        "verifier.frontend.images.baseUrl=https://cdn.example.com/assets",
                        "verifier.frontend.images.logoPath=logo.png"
                )
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void testMissingMandatoryImagesBaseUrlCausesError() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "verifier.frontend.urls.onboarding=https://example.com/onboarding",
                        "verifier.frontend.urls.support=https://example.com/support",
                        "verifier.frontend.urls.wallet=https://example.com/wallet",
                        "verifier.frontend.images.logoPath=logo.png"
                )
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void testMissingMandatoryLogoPathCausesError() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "verifier.frontend.urls.onboarding=https://example.com/onboarding",
                        "verifier.frontend.urls.support=https://example.com/support",
                        "verifier.frontend.urls.wallet=https://example.com/wallet",
                        "verifier.frontend.images.baseUrl=https://cdn.example.com/assets"
                        // omit logoPath
                        // "verifier.frontend.images.logoPath=logo.png"
                )
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void testWithAllMandatoryPropertiesAndNoOptional() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "verifier.frontend.urls.onboarding=https://example.com/onboarding",
                        "verifier.frontend.urls.support=https://example.com/support",
                        "verifier.frontend.urls.wallet=https://example.com/wallet",
                        "verifier.frontend.images.baseUrl=https://cdn.example.com/assets",
                        "verifier.frontend.images.logoPath=logo.png"
                        // faviconPath optional
                )
                .run(context -> assertThat(context).hasNotFailed());
    }
}
