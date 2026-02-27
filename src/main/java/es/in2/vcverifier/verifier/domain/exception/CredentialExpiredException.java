package es.in2.vcverifier.verifier.domain.exception;

public class CredentialExpiredException extends RuntimeException {
    public CredentialExpiredException(String message) {
        super(message);
    }
}
