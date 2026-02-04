package es.in2.vcverifier.exception.handler;

import es.in2.vcverifier.exception.*;
import es.in2.vcverifier.model.GlobalErrorMessage;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.NoSuchElementException;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(ResourceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public GlobalErrorMessage handleResourceNotFoundException(ResourceNotFoundException ex) {
        log.error("Resource not found", ex);
        return new GlobalErrorMessage("","","");
    }

    @ExceptionHandler(NoSuchElementException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public GlobalErrorMessage handleNoSuchElementException(NoSuchElementException ex) {
        log.error("Element not found", ex);
        return new GlobalErrorMessage("","","");
    }

    @ExceptionHandler(QRCodeGenerationException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public GlobalErrorMessage handleQRCodeGenerationException(QRCodeGenerationException ex) {
        log.error("QR Code Generation Failed", ex);
        return new GlobalErrorMessage("QR Code Generation Failed","","");
    }

    @ExceptionHandler(CredentialRevokedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public GlobalErrorMessage handleException(CredentialRevokedException ex) {
        log.error("The credential has been revoked: ", ex);
        return new GlobalErrorMessage("Verifiable presentation failed","","");
    }

    @ExceptionHandler(MismatchOrganizationIdentifierException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleException(MismatchOrganizationIdentifierException ex) {
        log.error("The organization identifier of the cert does not match the organization identifier from the credential payload: ", ex);
        return new GlobalErrorMessage("","","");
    }

    @ExceptionHandler(CredentialExpiredException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleException(CredentialExpiredException ex) {
        log.error("The credential has expired: ", ex);
        return new GlobalErrorMessage("","","");
    }

    @ExceptionHandler(CredentialNotActiveException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleException(CredentialNotActiveException ex) {
        log.error("The credential is not active yet: ", ex);
        return new GlobalErrorMessage("","","");
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public GlobalErrorMessage handleException(Exception ex) {
        log.error("An unexpected error occurred: ", ex);
        return new GlobalErrorMessage("","","");
    }

    @ExceptionHandler(InvalidVPtokenException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleException(InvalidVPtokenException ex, HttpServletRequest request) {
        String contextPath = request.getContextPath();
        log.error("VP token is not valid: {}", ex.getMessage());
        return new GlobalErrorMessage("Invalid VP Token", ex.getMessage(), contextPath);
    }

    @ExceptionHandler(LoginTimeoutException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleException(LoginTimeoutException ex) {
        log.error("Login time has expired ", ex.getMessage());
        return new GlobalErrorMessage("Login time has expired ",ex.getMessage(),"");
    }

    @ExceptionHandler(StatusListCredentialException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public GlobalErrorMessage handleStatusListCredentialException(StatusListCredentialException ex) {
        log.error("Error while handling Status List Credential ", ex.getMessage());
        return new GlobalErrorMessage("Error while handling Status List Credential ",ex.getMessage(),"");
    }
}

