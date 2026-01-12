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
        FrontendProperties.Assets assets = mock(FrontendProperties.Assets.class);

        when(frontendProperties.urls()).thenReturn(urls);
        when(frontendProperties.colors()).thenReturn(colors);
        when(frontendProperties.assets()).thenReturn(assets);

        when(assets.baseUrl()).thenReturn("https://cdn.example.com/assets");
        when(assets.logoPath()).thenReturn("logo.png");
        when(assets.faviconPath()).thenReturn("favicon.ico");

        assertThat(frontendConfig.getPrimaryColor()).isEqualTo("#2D58A7");
        assertThat(frontendConfig.getPrimaryContrastColor()).isEqualTo("#ffffff");
        assertThat(frontendConfig.getSecondaryColor()).isEqualTo("#14274A");
        assertThat(frontendConfig.getSecondaryContrastColor()).isEqualTo("#00ADD3");

        assertThat(frontendConfig.getLogoSrc()).isEqualTo("https://cdn.example.com/assets/logo.png");
        assertThat(frontendConfig.getFaviconSrc()).isEqualTo("https://cdn.example.com/assets/favicon.ico");
        assertThat(frontendConfig.getDefaultLang()).isEqualTo("en");
    }

    @Test
    void testFrontendConfigWithProvidedValues() {
        FrontendProperties.Urls urls = mock(FrontendProperties.Urls.class);
        FrontendProperties.Colors colors = mock(FrontendProperties.Colors.class);
        FrontendProperties.Assets assets = mock(FrontendProperties.Assets.class);

        when(frontendProperties.urls()).thenReturn(urls);
        when(frontendProperties.colors()).thenReturn(colors);
        when(frontendProperties.assets()).thenReturn(assets);

        when(frontendProperties.defaultLang()).thenReturn("en");
        when(colors.primary()).thenReturn("#123456");
        when(colors.primaryContrast()).thenReturn("#654321");
        when(colors.secondary()).thenReturn("#abcdef");
        when(colors.secondaryContrast()).thenReturn("#fedcba");

        when(assets.baseUrl()).thenReturn("https://cdn.example.com/assets/");
        when(assets.logoPath()).thenReturn("/custom_logo.png");
        when(assets.faviconPath()).thenReturn("custom_favicon.ico");

        assertThat(frontendConfig.getPrimaryColor()).isEqualTo("#123456");
        assertThat(frontendConfig.getPrimaryContrastColor()).isEqualTo("#654321");
        assertThat(frontendConfig.getSecondaryColor()).isEqualTo("#abcdef");
        assertThat(frontendConfig.getSecondaryContrastColor()).isEqualTo("#fedcba");

        assertThat(frontendConfig.getLogoSrc()).isEqualTo("https://cdn.example.com/assets/custom_logo.png");
        assertThat(frontendConfig.getFaviconSrc()).isEqualTo("https://cdn.example.com/assets/custom_favicon.ico");
        assertThat(frontendConfig.getDefaultLang()).isEqualTo("en");
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
