package es.in2.vcverifier.exception;

public class JWTVerificationException extends RuntimeException {

    public JWTVerificationException(String message) {
        super(message);
    }

    public JWTVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
