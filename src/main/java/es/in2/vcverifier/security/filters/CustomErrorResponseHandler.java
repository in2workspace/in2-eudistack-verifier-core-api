package es.in2.vcverifier.security.filters;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

import static es.in2.vcverifier.shared.domain.util.Constants.INVALID_CLIENT_AUTHENTICATION;
import static es.in2.vcverifier.shared.domain.util.Constants.REQUIRED_EXTERNAL_USER_AUTHENTICATION;

public class CustomErrorResponseHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        if (exception instanceof OAuth2AuthorizationCodeRequestAuthenticationException oAuth2Exception) {
            OAuth2Error error = oAuth2Exception.getError();
            // Redirect to the URI contained, if the error code is required_external_user_authentication or invalid_client_authentication
            if (error.getErrorCode().equals(REQUIRED_EXTERNAL_USER_AUTHENTICATION) || error.getErrorCode().equals(INVALID_CLIENT_AUTHENTICATION)) {
                response.sendRedirect(error.getUri());
                return;
            }
        }

        // Handle other unexpected errors
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Authentication failed");
    }
}

