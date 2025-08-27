package es.in2.vcverifier.service;

import com.fasterxml.jackson.databind.JsonNode;

public interface VpService {
    void validateVerifiablePresentation(String verifiablePresentation);
    Object getCredentialFromTheVerifiablePresentation(String verifiablePresentation);
    JsonNode getCredentialFromTheVerifiablePresentationAsJsonNode(String verifiablePresentation);
}
