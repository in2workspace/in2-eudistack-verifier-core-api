package es.in2.vcverifier.verifier.domain.exception;

public class CredentialNotActiveException extends RuntimeException {
    public CredentialNotActiveException(String message) {
        super(message);
    }
}
