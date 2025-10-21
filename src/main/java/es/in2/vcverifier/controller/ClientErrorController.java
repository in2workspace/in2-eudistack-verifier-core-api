package es.in2.vcverifier.controller;

import es.in2.vcverifier.config.FrontendConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.ui.Model;

import java.util.Locale;

@Slf4j
@Controller
@RequiredArgsConstructor
public class ClientErrorController {

    private final FrontendConfig frontendConfig;

    @GetMapping("/client-error")
    @ResponseStatus(HttpStatus.OK)
    public String showErrorPage(@RequestParam("errorCode") String errorCode,
                                @RequestParam("errorMessage") String errorMessage,
                                @RequestParam("clientUrl") String clientUrl,
                                @RequestParam("originalRequestURL") String originalRequestURL,
                                Locale locale,
                                Model model) {
        // Add attributes to the model
        model.addAttribute("errorCode", errorCode);
        model.addAttribute("errorMessage", errorMessage);
        model.addAttribute("clientUrl", clientUrl);
        model.addAttribute("supportUri", frontendConfig.getSupportUrl());
        model.addAttribute("originalRequestURL", originalRequestURL);

        model.addAttribute("primary", frontendConfig.getPrimaryColor());
        model.addAttribute("primaryContrast", frontendConfig.getPrimaryContrastColor());
        model.addAttribute("secondary", frontendConfig.getSecondaryColor());
        model.addAttribute("secondaryContrast", frontendConfig.getSecondaryContrastColor());
        model.addAttribute("faviconSrc", frontendConfig.getFaviconSrc());
        // Return the view name
        log.info("Browser requested locale: {}", locale);
        String language = locale.getLanguage().toLowerCase();
        return "client-authentication-error-" + frontendConfig.getDefaultLang();
    }

}
