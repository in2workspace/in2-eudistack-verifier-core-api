package es.in2.vcverifier.shared.config.properties;
import es.in2.vcverifier.config.properties.FrontendProperties;

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

        FrontendProperties.Assets expectedAssets = new FrontendProperties.Assets(
                "https://cdn.example.com/assets",
                "logo.png",
                "favicon.ico"
        );

        assertThat(frontendProperties.urls())
                .as("URLs should match the provided values")
                .isEqualTo(expectedUrls);

        assertThat(frontendProperties.colors())
                .as("Colors should match the provided values")
                .isEqualTo(expectedColors);

        assertThat(frontendProperties.assets())
                .as("Assets should match the provided values")
                .isEqualTo(expectedAssets);

        assertThat(frontendProperties.defaultLang())
                .as("Default lang should be en")
                .isEqualTo("en");
    }

    @Test
    void testAllFieldsAreOptional() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void testWithAllProperties() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                        "verifier.frontend.urls.onboarding=https://example.com/onboarding",
                        "verifier.frontend.urls.support=https://example.com/support",
                        "verifier.frontend.urls.wallet=https://example.com/wallet",
                        "verifier.frontend.assets.baseUrl=https://cdn.example.com/assets",
                        "verifier.frontend.assets.logoPath=logo.png",
                        "verifier.frontend.assets.faviconPath=favicon.ico",
                        "verifier.frontend.defaultLang=es"
                )
                .run(context -> assertThat(context).hasNotFailed());
    }

    @EnableConfigurationProperties(FrontendProperties.class)
    static class TestConfig {
    }
}
