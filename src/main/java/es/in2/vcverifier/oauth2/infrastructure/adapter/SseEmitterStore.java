package es.in2.vcverifier.oauth2.infrastructure.adapter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
public class SseEmitterStore {

    private final ConcurrentHashMap<String, SseEmitter> emitters = new ConcurrentHashMap<>();

    public SseEmitter create(String state, long timeoutMs) {
        SseEmitter emitter = new SseEmitter(timeoutMs);
        emitters.put(state, emitter);
        emitter.onCompletion(() -> emitters.remove(state));
        emitter.onTimeout(() -> emitters.remove(state));
        emitter.onError(e -> emitters.remove(state));
        log.debug("SSE emitter created for state={}, timeout={}ms", state, timeoutMs);
        return emitter;
    }

    public void send(String state, String redirectUrl) {
        SseEmitter emitter = emitters.remove(state);
        if (emitter != null) {
            try {
                emitter.send(SseEmitter.event().name("redirect").data(redirectUrl));
                emitter.complete();
                log.debug("SSE redirect event sent for state={}", state);
            } catch (IOException e) {
                log.warn("Failed to send SSE event for state={}: {}", state, e.getMessage());
                emitter.completeWithError(e);
            }
        } else {
            log.warn("No SSE emitter found for state={}", state);
        }
    }
}
