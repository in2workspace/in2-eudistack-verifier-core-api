package es.in2.vcverifier.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

@Configuration
@RequiredArgsConstructor
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    private final BackendConfig backendConfig;

    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        // Habilitar el broker solo para el canal /oidc
        config.enableSimpleBroker("/oidc");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        // Registrar el endpoint de WebSocket para que los clientes se conecten
        registry.addEndpoint("/qr-socket")
                .setAllowedOrigins(backendConfig.getUrl())
                .withSockJS();
    }
    
}

