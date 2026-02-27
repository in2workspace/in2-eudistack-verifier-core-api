package es.in2.vcverifier.oauth2.domain.exception;

public class UnsupportedGrantTypeException extends RuntimeException {

    public UnsupportedGrantTypeException(String message) {
        super(message);
    }

}
