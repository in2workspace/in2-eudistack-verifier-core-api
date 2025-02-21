package es.in2.vcverifier.oid4vp.controller;

import es.in2.vcverifier.config.FrontendConfig;
import es.in2.vcverifier.controller.LoginQrController;
import es.in2.vcverifier.exception.QRCodeGenerationException;
import net.glxn.qrgen.javase.QRCode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ui.Model;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

import static es.in2.vcverifier.util.Constants.LOGIN_TIMEOUT;
import static es.in2.vcverifier.util.Constants.LOGIN_TIMEOUT_CRON_UNIT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LoginQrControllerTest {

    @InjectMocks
    private LoginQrController loginQrController;

    @Mock
    private Model model;

    @Mock
    private FrontendConfig frontendConfig;

    @Test
    void showQrLogin_validAuthRequest_shouldReturnLoginView() {
        // Given
        String authRequest = "validAuthRequest";
        String state = "validState";
        String homeUri = "homeUri";

        byte[] qrBytes = "mockedQRCode".getBytes(); // Simulating QR Code bytes
        ByteArrayOutputStream byteArrayOutputStream = spy(new ByteArrayOutputStream());
        when(byteArrayOutputStream.toByteArray()).thenReturn(qrBytes);

        // Mocking Frontend Config
        when(frontendConfig.getOnboardingUrl()).thenReturn("onboardingUri");
        when(frontendConfig.getSupportUrl()).thenReturn("supportUri");
        when(frontendConfig.getWalletUrl()).thenReturn("walletUri");
        when(frontendConfig.getPrimaryColor()).thenReturn("#0000FF");
        when(frontendConfig.getPrimaryContrastColor()).thenReturn("#FFFFFF");
        when(frontendConfig.getSecondaryColor()).thenReturn("#00FF00");
        when(frontendConfig.getSecondaryContrastColor()).thenReturn("#000000");
        when(frontendConfig.getLogoSrc()).thenReturn("img/no-image.png");
        when(frontendConfig.getFaviconSrc()).thenReturn("img/favicon.ico");

        try (MockedStatic<QRCode> qrCodeMock = Mockito.mockStatic(QRCode.class)) {
            QRCode qrCodeInstance = mock(QRCode.class);
            qrCodeMock.when(() -> QRCode.from(authRequest)).thenReturn(qrCodeInstance);
            when(qrCodeInstance.withSize(250, 250)).thenReturn(qrCodeInstance);
            when(qrCodeInstance.stream()).thenReturn(byteArrayOutputStream);

            // When
            String viewName = loginQrController.showQrLogin(authRequest, state, model, homeUri);

            // Then
            assertEquals("login", viewName);

            verify(model).addAttribute("qrImage", "data:image/png;base64," + Base64.getEncoder().encodeToString(qrBytes));
            verify(model).addAttribute("authRequest", authRequest);
            verify(model).addAttribute("state", state);
            verify(model).addAttribute("homeUri", homeUri);
            verify(model).addAttribute("onboardingUri", "onboardingUri");
            verify(model).addAttribute("supportUri", "supportUri");
            verify(model).addAttribute("walletUri", "walletUri");
            verify(model).addAttribute("primary", "#0000FF");
            verify(model).addAttribute("primaryContrast", "#FFFFFF");
            verify(model).addAttribute("secondary", "#00FF00");
            verify(model).addAttribute("secondaryContrast", "#000000");
            verify(model).addAttribute("logoSrc", "img/no-image.png");
            verify(model).addAttribute("faviconSrc", "img/favicon.ico");
            verify(model).addAttribute("expiration", LOGIN_TIMEOUT);
            verify(model).addAttribute("cronUnit", LOGIN_TIMEOUT_CRON_UNIT);
        }
    }

    @Test
    void showQrLogin_exceptionDuringQRCodeGeneration_shouldThrowQRCodeGenerationException() {
        // Given
        String authRequest = "invalidAuthRequest";
        String state = "validState";

        try (MockedStatic<QRCode> qrCodeMock = Mockito.mockStatic(QRCode.class)) {
            qrCodeMock.when(() -> QRCode.from(authRequest)).thenThrow(new RuntimeException("QR Code Generation Failed"));

            // When & Then
            QRCodeGenerationException exception = assertThrows(QRCodeGenerationException.class, () ->
                    loginQrController.showQrLogin(authRequest, state, model, "homeUri")
            );

            assertEquals("QR Code Generation Failed", exception.getMessage());
        }
    }
}
