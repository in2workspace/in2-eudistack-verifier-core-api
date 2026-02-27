package es.in2.vcverifier.verifier.domain.exception;

public class RemoteFileFetchException extends RuntimeException {
    public RemoteFileFetchException(String message) {
        super(message);
    }

    public RemoteFileFetchException(String message, Throwable cause) {
        super(message, cause);
    }
}
