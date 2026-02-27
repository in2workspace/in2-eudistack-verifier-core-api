package es.in2.vcverifier.oauth2.domain.exception;

public class LoginTimeoutException extends  RuntimeException {
    public LoginTimeoutException(String message){
        super(message);
    }
}
