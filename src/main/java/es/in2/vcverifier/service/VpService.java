package es.in2.vcverifier.service;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

public interface VpService {
    void validateVerifiablePresentation(String verifiablePresentation);
    Object getCredentialFromTheVerifiablePresentation(String verifiablePresentation);
    JsonNode getCredentialFromTheVerifiablePresentationAsJsonNode(String verifiablePresentation);
    public List<String> extractContextFromJson(JsonNode verifiableCredential);
}
