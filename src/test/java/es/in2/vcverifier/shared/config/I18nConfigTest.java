package es.in2.vcverifier.shared.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;

import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

class I18nConfigTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(I18nConfig.class);

    @Test
    void localeResolver_shouldBeAcceptHeaderLocaleResolver_withConfiguredSupportedLocales_andDefaultViaResolution() {
        contextRunner.run(ctx -> {
            assertTrue(ctx.containsBean("localeResolver"));

            LocaleResolver resolver = ctx.getBean(LocaleResolver.class);
            assertNotNull(resolver);
            assertInstanceOf(AcceptHeaderLocaleResolver.class, resolver);

            AcceptHeaderLocaleResolver ahlr = (AcceptHeaderLocaleResolver) resolver;

            // Supported locales must be exactly [en, es, ca] in order
            List<Locale> expectedSupported = List.of(
                    Locale.forLanguageTag("en"),
                    Locale.forLanguageTag("es"),
                    Locale.forLanguageTag("ca")
            );
            assertEquals(expectedSupported, ahlr.getSupportedLocales());

            // Default locale: resolve with no Accept-Language header -> English
            MockHttpServletRequest reqNoHeader = new MockHttpServletRequest();
            Locale resolvedNoHeader = ahlr.resolveLocale(reqNoHeader);
            assertEquals(Locale.ENGLISH, resolvedNoHeader,
                    "When no Accept-Language is present, resolver should return English");

            // If header is unsupported -> fallback to default (English)
            MockHttpServletRequest reqUnsupported = new MockHttpServletRequest();
            reqUnsupported.addHeader("Accept-Language", "fr-FR");
            Locale resolvedUnsupported = ahlr.resolveLocale(reqUnsupported);
            assertEquals(Locale.ENGLISH, resolvedUnsupported,
                    "When Accept-Language is unsupported, it should fall back to English");

            // If header is supported -> honor it
            MockHttpServletRequest reqSupported = new MockHttpServletRequest();
            reqSupported.addHeader("Accept-Language", "es-ES,es;q=0.9");
            Locale resolvedSupported = ahlr.resolveLocale(reqSupported);
            assertEquals(Locale.forLanguageTag("es"), resolvedSupported,
                    "When Accept-Language is supported, it should resolve to that locale (es)");
        });
    }
}
