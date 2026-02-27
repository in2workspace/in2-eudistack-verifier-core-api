package es.in2.vcverifier.verifier.infrastructure.adapter;

import es.in2.vcverifier.verifier.domain.service.TranslationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;
import org.springframework.stereotype.Service;

import java.util.Locale;

@Slf4j
@Service
@RequiredArgsConstructor
public class TranslationServiceImpl implements TranslationService {

    private final MessageSource messageSource;

    @Override
    public String getLocale() {
        return "en";
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

