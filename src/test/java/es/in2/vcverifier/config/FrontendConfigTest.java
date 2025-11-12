package es.in2.vcverifier.config;

import es.in2.vcverifier.config.properties.FrontendProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SpringBootTest(classes = {FrontendConfig.class, FrontendConfigImplTest.DefaultTestConfig.class})
class FrontendConfigImplTest {

    @Autowired
    private FrontendConfig frontendConfig;

    @MockBean
    private FrontendProperties frontendProperties;

    @Test
    void testFrontendConfigWithDefaults() {
        FrontendProperties.Urls urls = mock(FrontendProperties.Urls.class);
        FrontendProperties.Colors colors = mock(FrontendProperties.Colors.class);

        when(frontendProperties.urls()).thenReturn(urls);
        when(frontendProperties.colors()).thenReturn(colors);
        when(frontendProperties.logoSrc()).thenReturn(null);
        when(frontendProperties.faviconSrc()).thenReturn(null);

        assertThat(frontendConfig.getPrimaryColor()).isEqualTo("#2D58A7");
        assertThat(frontendConfig.getPrimaryContrastColor()).isEqualTo("#ffffff");
        assertThat(frontendConfig.getSecondaryColor()).isEqualTo("#14274A");
        assertThat(frontendConfig.getSecondaryContrastColor()).isEqualTo("#00ADD3");
        assertThat(frontendConfig.getFaviconSrc()).isEqualTo("dome_logo_favicon.png");
        assertThat(frontendConfig.getDefaultLang()).isEqualTo("en");
    }

    @Test
    void testFrontendConfigWithProvidedValues() {
        FrontendProperties.Urls urls = mock(FrontendProperties.Urls.class);
        FrontendProperties.Colors colors = mock(FrontendProperties.Colors.class);

        when(frontendProperties.urls()).thenReturn(urls);
        when(frontendProperties.colors()).thenReturn(colors);
        when(frontendProperties.logoSrc()).thenReturn("custom_logo.png");
        when(frontendProperties.faviconSrc()).thenReturn("custom_favicon.ico");
        when(frontendProperties.defaultLang()).thenReturn("en");
        when(colors.primary()).thenReturn("#123456");
        when(colors.primaryContrast()).thenReturn("#654321");
        when(colors.secondary()).thenReturn("#abcdef");
        when(colors.secondaryContrast()).thenReturn("#fedcba");

        assertThat(frontendConfig.getPrimaryColor()).isEqualTo("#123456");
        assertThat(frontendConfig.getPrimaryContrastColor()).isEqualTo("#654321");
        assertThat(frontendConfig.getSecondaryColor()).isEqualTo("#abcdef");
        assertThat(frontendConfig.getSecondaryContrastColor()).isEqualTo("#fedcba");
        assertThat(frontendConfig.getFaviconSrc()).isEqualTo("custom_favicon.ico");
        assertThat(frontendConfig.getDefaultLang()).isEqualTo("en");
        assertThat(frontendConfig.getLogoSrc()).isEqualTo("custom_logo.png");
    }

    @Configuration
    @EnableAutoConfiguration
    static class DefaultTestConfig {
        @Bean
        public FrontendProperties frontendProperties() {
            return mock(FrontendProperties.class);
        }
    }
}
