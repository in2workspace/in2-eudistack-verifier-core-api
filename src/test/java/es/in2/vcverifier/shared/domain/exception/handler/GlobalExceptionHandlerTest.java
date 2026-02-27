package es.in2.vcverifier.shared.domain.exception.handler;

import es.in2.vcverifier.verifier.domain.exception.*;
import es.in2.vcverifier.oauth2.domain.exception.*;
import es.in2.vcverifier.shared.domain.exception.*;
import es.in2.vcverifier.shared.domain.model.GlobalErrorMessage;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.login.CredentialExpiredException;
import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GlobalExceptionHandlerTest {

    @InjectMocks
    private GlobalExceptionHandler globalExceptionHandler;

    @Mock
    private HttpServletRequest mockRequest;

    @Test
    void testHandleResourceNotFoundException() {
        ResourceNotFoundException exception = new ResourceNotFoundException("Resource not found");

        GlobalErrorMessage response = globalExceptionHandler.handleResourceNotFoundException(exception);

        assertThat(response.title()).isEmpty();
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleNoSuchElementException() {
        NoSuchElementException exception = new NoSuchElementException("Element not found");

        GlobalErrorMessage response = globalExceptionHandler.handleNoSuchElementException(exception);

        assertThat(response.title()).isEmpty();
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleCredentialRevokedException() {
        CredentialRevokedException exception = new CredentialRevokedException("Credential revoked");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertThat(response.title()).isEqualTo("Verifiable presentation failed");
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleMismatchOrganizationIdentifierException() {
        MismatchOrganizationIdentifierException exception = new MismatchOrganizationIdentifierException("Mismatch org identifier");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertThat(response.title()).isEmpty();
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleGenericException() {
        Exception exception = new Exception("Generic error");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertThat(response.title()).isEmpty();
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleInvalidVPtokenException() {
        InvalidVPtokenException exception = new InvalidVPtokenException("Invalid VP token");

        // Stub the contextPath value
        when(mockRequest.getContextPath()).thenReturn("/test-path");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception, mockRequest);

        assertThat(response.title()).isEqualTo("Invalid VP Token");
        assertThat(response.message()).isEqualTo("Invalid VP token");
        assertThat(response.path()).isEqualTo("/test-path");
    }

    @Test
    void testHandleCredentialExpiredException() {
        CredentialExpiredException exception = new CredentialExpiredException("Credential expired");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertThat(response.title()).isEmpty();
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleCredentialNotActiveException() {
        CredentialNotActiveException exception = new CredentialNotActiveException("Credential not active");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertThat(response.title()).isEmpty();
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleStatusListCredentialException() {
        StatusListCredentialException exception = new StatusListCredentialException("Status list error");

        GlobalErrorMessage response = globalExceptionHandler.handleStatusListCredentialException(exception);

        assertThat(response.title()).isEqualTo("Error while handling Status List Credential ");
        assertThat(response.message()).isEqualTo("Status list error");
        assertThat(response.path()).isEmpty();
    }
}
