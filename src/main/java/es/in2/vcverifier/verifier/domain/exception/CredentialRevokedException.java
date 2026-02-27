package es.in2.vcverifier.verifier.domain.exception;

public class CredentialRevokedException extends RuntimeException {
    public CredentialRevokedException(String message) {
        super(message);
    }
}

