package es.in2.vcverifier.oauth2.domain.exception;

public class RequestMismatchException extends RuntimeException{

    public RequestMismatchException(String message) {
        super(message);
    }

}
