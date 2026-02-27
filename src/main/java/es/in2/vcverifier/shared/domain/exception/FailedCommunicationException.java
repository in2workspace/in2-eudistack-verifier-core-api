package es.in2.vcverifier.shared.domain.exception;

public class FailedCommunicationException extends RuntimeException {

    public FailedCommunicationException(String message) {
        super(message);
    }

}