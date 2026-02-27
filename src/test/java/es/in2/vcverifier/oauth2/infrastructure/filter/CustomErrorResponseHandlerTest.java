package es.in2.vcverifier.oauth2.infrastructure.filter;
import es.in2.vcverifier.security.filters.CustomErrorResponseHandler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;

import java.io.IOException;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomErrorResponseHandlerTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @InjectMocks
    private CustomErrorResponseHandler customErrorResponseHandler;

    @Test
    void testOnAuthenticationFailure_WithRequiredExternalUserAuthenticationError_ShouldRedirect() throws IOException {
        String redirectUri = "https://example.com/login";
        OAuth2Error oauth2Error = new OAuth2Error(
                "required_external_user_authentication",
                "Redirection required",
                redirectUri
        );
        AuthenticationException exception = new OAuth2AuthorizationCodeRequestAuthenticationException(oauth2Error, null);

        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        verify(response).sendRedirect(redirectUri);
        verify(response, never()).sendError(anyInt(), anyString());
    }

    @Test
    void testOnAuthenticationFailure_WithInvalidClientAuthenticationError_ShouldRedirect() throws IOException {
        String redirectUri = "https://example.com/error";
        OAuth2Error oauth2Error = new OAuth2Error(
                "invalid_client_authentication",
                "Invalid client authentication",
                redirectUri
        );
        AuthenticationException exception = new OAuth2AuthorizationCodeRequestAuthenticationException(oauth2Error, null);

        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        verify(response).sendRedirect(redirectUri);
        verify(response, never()).sendError(anyInt(), anyString());
    }

    @Test
    void testOnAuthenticationFailure_WithOAuth2Exception_OtherErrorCode_ShouldSendError() throws IOException {
        OAuth2Error oauth2Error = new OAuth2Error("invalid_request", "Invalid request", null);
        AuthenticationException exception = new OAuth2AuthorizationCodeRequestAuthenticationException(oauth2Error, null);

        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        verify(response, never()).sendRedirect(anyString());
        verify(response).sendError(HttpServletResponse.SC_BAD_REQUEST, "Authentication failed");
    }

    @Test
    void testOnAuthenticationFailure_WithOtherAuthenticationException_ShouldSendError() throws IOException {
        AuthenticationException exception = mock(AuthenticationException.class);

        customErrorResponseHandler.onAuthenticationFailure(request, response, exception);

        verify(response, never()).sendRedirect(anyString());
        verify(response).sendError(HttpServletResponse.SC_BAD_REQUEST, "Authentication failed");
    }

}
