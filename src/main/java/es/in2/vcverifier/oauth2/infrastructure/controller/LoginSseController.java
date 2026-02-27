package es.in2.vcverifier.oauth2.infrastructure.controller;

import es.in2.vcverifier.oauth2.infrastructure.adapter.SseEmitterStore;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import static es.in2.vcverifier.shared.domain.util.Constants.LOGIN_TIMEOUT;

@RestController
@RequestMapping("/api/login")
@RequiredArgsConstructor
public class LoginSseController {

    private final SseEmitterStore sseEmitterStore;

    @GetMapping(value = "/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter subscribe(@RequestParam String state) {
        long timeoutMs = Long.parseLong(LOGIN_TIMEOUT) * 1000L;
        return sseEmitterStore.create(state, timeoutMs);
    }
}
