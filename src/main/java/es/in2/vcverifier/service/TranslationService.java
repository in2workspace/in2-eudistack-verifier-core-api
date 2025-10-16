package es.in2.vcverifier.service;

public interface TranslationService {
    public String getLocale();
    public String translate(String code, Object... args);
}

