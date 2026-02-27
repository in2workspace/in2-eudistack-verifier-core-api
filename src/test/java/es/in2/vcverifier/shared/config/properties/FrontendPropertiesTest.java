package es.in2.vcverifier.shared.config.properties;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = FrontendPropertiesTest.TestConfig.class)
@ActiveProfiles("test")
class FrontendPropertiesTest {

    @Autowired
    private FrontendProperties frontendProperties;

    @Test
    void testFrontendProperties() {
        assertThat(frontendProperties.portalUrl())
                .as("Portal URL should match the test config value")
                .isEqualTo("http://localhost:4200");
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
                        "verifier.frontend.portalUrl=http://portal.example.com"
                )
                .run(context -> assertThat(context).hasNotFailed());
    }

    @EnableConfigurationProperties(FrontendProperties.class)
    static class TestConfig {
    }
}
