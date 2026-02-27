package es.in2.vcverifier.verifier.domain.service;

public interface AuthorizationResponseProcessorService {
    void processAuthResponse(String state, String vpToken);
}
