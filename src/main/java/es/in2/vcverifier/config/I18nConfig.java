package es.in2.vcverifier.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;

import java.util.List;
import java.util.Locale;
import org.springframework.web.servlet.LocaleResolver;

@Configuration
public class I18nConfig implements WebMvcConfigurer {
    @Bean
    public LocaleResolver localeResolver(FrontendConfig frontendConfig) {
        AcceptHeaderLocaleResolver r = new AcceptHeaderLocaleResolver();
        r.setSupportedLocales(List.of(
                Locale.forLanguageTag("en"),
                Locale.forLanguageTag("es"),
                Locale.forLanguageTag("ca")
        ));

        r.setDefaultLocale(Locale.forLanguageTag(frontendConfig.getDefaultLang()));
        return r;
    }
}
