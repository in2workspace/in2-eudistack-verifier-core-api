package es.in2.vcverifier.controller;

import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.exception.ResourceNotFoundException;
import es.in2.vcverifier.model.AuthorizationRequestJWT;
import es.in2.vcverifier.service.AuthorizationResponseProcessorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/oid4vp")
@RequiredArgsConstructor
public class Oid4vpController {

    private final CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;
    private final AuthorizationResponseProcessorService authorizationResponseProcessorService;

    // Este método manejará las solicitudes GET al endpoint
    @GetMapping("/auth-request/{id}")
    @ResponseStatus(HttpStatus.OK)
    public String getAuthorizationRequest(@PathVariable String id) {

        System.out.println("XIVATO1");

        AuthorizationRequestJWT authorizationRequestJWT = cacheStoreForAuthorizationRequestJWT.get(id);
        System.out.println("XIVATO2");
        cacheStoreForAuthorizationRequestJWT.delete(id);
        System.out.println("XIVATO3");
        String jwt = authorizationRequestJWT.authRequest();

        if (jwt != null) {
            return jwt;
        } else {
            throw new ResourceNotFoundException("JWT not found for id: " + id);
        }
    }

    @PostMapping("/auth-response")
    @ResponseStatus(HttpStatus.OK)
    public void processAuthResponse(
            @RequestParam("state") String state,
            @RequestParam("vp_token") String vpToken,
            @RequestParam(value = "presentation_submission", required = false) String presentationSubmission) {
        //TODO We need use presentationSubmission in the future
        log.info("Processing auth response");
        log.debug("Oid4vpController -- processAuthResponse -- Request params: state = {}, vpToken = {}, presentationSubmission = {}", state, vpToken, presentationSubmission);
        authorizationResponseProcessorService.processAuthResponse(state, vpToken); //PASA POR AQUI
    }

}
