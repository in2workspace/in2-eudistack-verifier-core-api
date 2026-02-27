package es.in2.vcverifier.verifier.infrastructure.adapter;

import es.in2.vcverifier.shared.config.FrontendConfig;
import es.in2.vcverifier.verifier.domain.service.TranslationService;
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

        if (locale == null || locale.isBlank()) {
            log.warn("No default language configured. Using fallback: 'en'");
            return "en";
        }

        locale = locale.trim().toLowerCase();

        if (!SUPPORTED_LANGS.contains(locale)) {
            log.warn("Unsupported language '{}'. Falling back to 'en'", locale);
            return "en";
        }
        return locale;
    }

    @Override
    public String translate(String code, Object... args) {
        var locale = Locale.forLanguageTag(getLocale());
        try {
            return messageSource.getMessage(code, args, locale);
        } catch (NoSuchMessageException e) {
            log.warn("Message code '{}' not found for locale {}. Falling back to code.", code, locale);
            return code;
        }
    }
}

