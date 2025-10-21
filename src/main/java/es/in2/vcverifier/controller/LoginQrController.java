package es.in2.vcverifier.controller;

import static es.in2.vcverifier.util.Constants.LOGIN_TIMEOUT;
import static es.in2.vcverifier.util.Constants.LOGIN_TIMEOUT_CHRONO_UNIT;

import es.in2.vcverifier.config.FrontendConfig;
import es.in2.vcverifier.exception.QRCodeGenerationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.glxn.qrgen.javase.QRCode;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.Locale;

@Slf4j
@Controller
@RequiredArgsConstructor
public class LoginQrController {

    private final FrontendConfig frontendConfig;

    @GetMapping("/login")
    @ResponseStatus(HttpStatus.OK)
    public String showQrLogin(@RequestParam("authRequest") String authRequest, @RequestParam("state") String state, Model model, Locale locale,  @RequestParam("homeUri") String homeUri) {
        try {
            // Generar la imagen QR en base64
            String qrImageBase64 = generateQRCodeImageBase64(authRequest);
            // Pasar el QR en base64 y el authRequest en texto al modelo
            model.addAttribute("qrImage", "data:image/png;base64," + qrImageBase64);
            model.addAttribute("authRequest", authRequest);
            // Pasar el sessionId al modelo
            model.addAttribute("state", state);
            model.addAttribute("homeUri", homeUri);
            model.addAttribute("onboardingUri", frontendConfig.getOnboardingUrl());
            model.addAttribute("supportUri", frontendConfig.getSupportUrl());
            model.addAttribute("walletUri", frontendConfig.getWalletUrl());
            model.addAttribute("primary", frontendConfig.getPrimaryColor());
            model.addAttribute("primaryContrast", frontendConfig.getPrimaryContrastColor());
            model.addAttribute("secondary", frontendConfig.getSecondaryColor());
            model.addAttribute("secondaryContrast", frontendConfig.getSecondaryContrastColor());
            model.addAttribute("logoSrc", frontendConfig.getLogoSrc());
            model.addAttribute("faviconSrc", frontendConfig.getFaviconSrc());
            model.addAttribute("expiration", LOGIN_TIMEOUT);
            model.addAttribute("cronUnit", LOGIN_TIMEOUT_CHRONO_UNIT);

        } catch (Exception e) {
            throw new QRCodeGenerationException(e.getMessage());
        }
        log.info("Browser requested locale: {}", locale);
        String language = locale.getLanguage().toLowerCase();
        return "login-" + language;
    }

    private String generateQRCodeImageBase64(String barcodeText) {
        ByteArrayOutputStream stream = QRCode
                .from(barcodeText)
                .withSize(250, 250)
                .stream();
        byte[] imageBytes = stream.toByteArray();
        return Base64.getEncoder().encodeToString(imageBytes);
    }

}
