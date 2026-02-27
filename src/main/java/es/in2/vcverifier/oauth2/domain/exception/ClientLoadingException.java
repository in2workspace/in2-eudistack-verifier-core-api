package es.in2.vcverifier.oauth2.domain.exception;

public class ClientLoadingException extends RuntimeException{

    public ClientLoadingException(String message, Throwable cause) {
        super(message, cause);
    }
}
