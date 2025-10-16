package es.in2.vcverifier.service.impl;

import es.in2.vcverifier.config.FrontendConfig;
import es.in2.vcverifier.service.TranslationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;

@Slf4j
@Service
@RequiredArgsConstructor
public class TranslationServiceImpl implements TranslationService {

    private final FrontendConfig frontendConfig;
    private final MessageSource messageSource;

    private static final List<String> SUPPORTED_LANGS = List.of("en", "es");

    @Override
    public String getLocale() {
        String locale = frontendConfig.getDefaultLang();
        log.info("Default lang from config: {}", locale);

        if (locale == null || locale.isBlank()) {
            log.warn("No default language configured. Using fallback: 'en'");
            return "en";
        }

        locale = locale.trim().toLowerCase();

        if (!SUPPORTED_LANGS.contains(locale)) {
            log.warn("Unsupported language '{}'. Falling back to 'en'", locale);
            return "en";
        }
        log.info("Using locale: {}", locale);
        return locale;
    }

    @Override
    public String translate(String code, Object... args) {
        var locale = Locale.forLanguageTag(getLocale());
        try {
            log.info("code: {}", code);
            log.info("args: {}", args);
            log.info("locale: {}", locale);
            return messageSource.getMessage(code, args, locale);
        } catch (NoSuchMessageException e) {
            log.warn("Message code '{}' not found for locale {}. Falling back to code.", code, locale);
            return code;
        }
    }
}

