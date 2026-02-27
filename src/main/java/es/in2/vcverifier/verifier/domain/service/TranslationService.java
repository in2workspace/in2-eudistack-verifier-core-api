package es.in2.vcverifier.verifier.domain.service;

public interface TranslationService {
    public String getLocale();
    public String translate(String code, Object... args);
}

