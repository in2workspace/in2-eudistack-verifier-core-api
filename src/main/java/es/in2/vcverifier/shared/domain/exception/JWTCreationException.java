package es.in2.vcverifier.shared.domain.exception;

public class JWTCreationException extends RuntimeException {

    public JWTCreationException(String message) {
        super(message);
    }

}
