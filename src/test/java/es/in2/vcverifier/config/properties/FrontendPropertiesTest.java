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

        assertThat(frontendProperties.urls())
                .as("URLs should match the provided values")
                .isEqualTo(expectedUrls);

        assertThat(frontendProperties.colors())
                .as("Colors should match the provided values")
                .isEqualTo(expectedColors);

        assertThat(frontendProperties.logoSrc())
                .as("Logo source should be 'logo.png'")
                .isEqualTo("logo.png");

        assertThat(frontendProperties.faviconSrc())
                .as("Favicon source should be 'favicon.ico'")
                .isEqualTo("favicon.ico");

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
                        // omit onboarding url
                        // "verifier.frontend.urls.onboarding"
                        "verifier.frontend.urls.support=https://example.com/support",
                        "verifier.frontend.urls.wallet=https://example.com/wallet",
                        "verifier.frontend.logoSrc=logo.png"
                )
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void testMissingMandatorySupportUrlCausesError() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                         "verifier.frontend.urls.onboarding=https://example.com/onboarding",
                        // omit support url
                        //  "verifier.frontend.urls.support=https://example.com/support",
                        "verifier.frontend.urls.wallet=https://example.com/wallet",
                        "verifier.frontend.logoSrc=logo.png"
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
                        // omit wallet url
                        //  "verifier.frontend.urls.wallet=https://example.com/wallet",
                        "verifier.frontend.logoSrc=logo.png"
                )
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void testMissingMandatoryLogoSrcCausesError() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues(
                         "verifier.frontend.urls.onboarding=https://example.com/onboarding",
                        "verifier.frontend.urls.support=https://example.com/support",
                          "verifier.frontend.urls.wallet=https://example.com/wallet"
                        //omit logoSrc
//                        "verifier.frontend.logoSrc=logo.png"
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
                        "verifier.frontend.logoSrc=logo.png"
                )
                .run(context -> assertThat(context).hasNotFailed());
    }
}
