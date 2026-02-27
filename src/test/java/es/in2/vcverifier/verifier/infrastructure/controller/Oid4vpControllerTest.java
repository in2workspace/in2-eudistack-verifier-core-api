package es.in2.vcverifier.verifier.infrastructure.controller;

import es.in2.vcverifier.verifier.infrastructure.controller.Oid4vpController;
import es.in2.vcverifier.shared.domain.exception.ResourceNotFoundException;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationRequestJWT;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import es.in2.vcverifier.shared.config.CacheStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class Oid4vpControllerTest {

    @InjectMocks
    private Oid4vpController oid4vpController;

    @Mock
    private CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;

    @Mock
    private AuthorizationResponseProcessorService authorizationResponseProcessorService;

    @Test
    void getAuthorizationRequest_validId_shouldReturnJwt() {
        String id = "validId";
        String expectedJwt = "sampleJwt";
        AuthorizationRequestJWT mockAuthRequestJWT = Mockito.mock(AuthorizationRequestJWT.class);

        when(cacheStoreForAuthorizationRequestJWT.get(id)).thenReturn(mockAuthRequestJWT);
        when(mockAuthRequestJWT.authRequest()).thenReturn(expectedJwt);

        String resultJwt = oid4vpController.getAuthorizationRequest(id);

        assertEquals(expectedJwt, resultJwt);
        Mockito.verify(cacheStoreForAuthorizationRequestJWT).delete(id);
    }

    @Test
    void getAuthorizationRequest_invalidId_shouldThrowResourceNotFoundException() {
        String id = "invalidId";

        AuthorizationRequestJWT authorizationRequestJWT = AuthorizationRequestJWT.builder().authRequest(null).build();
        when(cacheStoreForAuthorizationRequestJWT.get(id)).thenReturn(authorizationRequestJWT);

        ResourceNotFoundException exception = assertThrows(ResourceNotFoundException.class, () ->
                oid4vpController.getAuthorizationRequest(id)
        );

        assertEquals("JWT not found for id: " + id, exception.getMessage());
    }

    @Test
    void processAuthResponse_validParameters_shouldInvokeService() {
        String state = "validState";
        String vpToken = "validVpToken";
        String presentationSubmission = "validPresentationSubmission"; // Aunque no se usa, se puede pasar

        oid4vpController.processAuthResponse(state, vpToken, presentationSubmission);

        Mockito.verify(authorizationResponseProcessorService).processAuthResponse(state, vpToken);
    }

}
