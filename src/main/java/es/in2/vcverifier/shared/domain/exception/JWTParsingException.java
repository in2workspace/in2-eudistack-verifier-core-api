package es.in2.vcverifier.shared.domain.exception;

public class JWTParsingException extends RuntimeException{

    public JWTParsingException(String message) {
        super(message);
    }

}
