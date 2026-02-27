package es.in2.vcverifier.verifier.domain.exception;

public class IssuerNotAuthorizedException extends RuntimeException {
    public IssuerNotAuthorizedException(String message) {
        super(message);
    }
}
