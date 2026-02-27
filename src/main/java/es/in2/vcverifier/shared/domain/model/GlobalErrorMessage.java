package es.in2.vcverifier.shared.domain.model;

import lombok.Builder;

@Builder
public record GlobalErrorMessage(String title, String message, String path) { }