package es.in2.vcverifier.verifier.infrastructure.adapter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(MockitoExtension.class)
class TranslationServiceImplTest {

    @Mock
    private MessageSource messageSource;

    private TranslationServiceImpl service;

    @Captor
    private ArgumentCaptor<Object[]> argsCaptor;

    @Captor
    private ArgumentCaptor<Locale> localeCaptor;

    @BeforeEach
    void setUp() {
        service = new TranslationServiceImpl(messageSource);
    }

    @Test
    @DisplayName("getLocale() always returns 'en'")
    void getLocale_alwaysReturnsEnglish() {
        assertEquals("en", service.getLocale());
    }

    @Test
    @DisplayName("translate() returns localized message from MessageSource with correct args and locale")
    void translate_returnsMessage_andUsesLocaleAndArgs() {
        when(messageSource.getMessage(eq("greeting"), any(), any()))
                .thenReturn("Hello, Roger");

        String result = service.translate("greeting", "Roger");

        assertThat(result).isEqualTo("Hello, Roger");

        verify(messageSource).getMessage(eq("greeting"), argsCaptor.capture(), localeCaptor.capture());

        Object[] passedArgs = argsCaptor.getValue();
        assertThat(passedArgs)
                .isNotNull()
                .hasSize(1)
                .containsExactly("Roger");

        Locale passedLocale = localeCaptor.getValue();
        assertThat(passedLocale)
                .isNotNull()
                .extracting(Locale::getLanguage)
                .isEqualTo("en");
    }

    @Test
    @DisplayName("translate() falls back to code when message is missing")
    void translate_fallsBackToCodeOnMissingMessage() {
        when(messageSource.getMessage(eq("missing.key"), any(), any()))
                .thenThrow(new NoSuchMessageException("missing.key"));

        String result = service.translate("missing.key", 123);

        assertThat(result).isEqualTo("missing.key");

        verify(messageSource).getMessage(eq("missing.key"), any(), localeCaptor.capture());
        assertThat(localeCaptor.getValue().getLanguage()).isEqualTo("en");
    }
}
