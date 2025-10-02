package es.in2.vcverifier.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.server.HandshakeInterceptor;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

@Configuration
@RequiredArgsConstructor
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    private final Set<String> allowedClientsOrigins;

    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        // Habilitar el broker solo para el canal /oidc
        config.enableSimpleBroker("/oidc");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        // Registrar el endpoint de WebSocket para que los clientes se conecten
        registry.addEndpoint("/qr-socket")
                .addInterceptors(new LoggingHandshakeInterceptor());
    }

    private class LoggingHandshakeInterceptor implements HandshakeInterceptor {

        @Override
        public boolean beforeHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler, Map<String, Object> attributes) {

            String origin = request.getHeaders().getOrigin();
            System.out.println("headers: " + request.getHeaders());
            System.out.println("WebSocket handshake attempt from Origin: " + origin);
            System.out.println("Allowed: " + allowedClientsOrigins);
            System.out.println("hiii");
            byte[] originBytes = request.getHeaders().getOrigin().getBytes(StandardCharsets.UTF_8);
            System.out.println("bytes:" + Arrays.toString(originBytes));
            return true;
        }

        @Override
        public void afterHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler, Exception exception) {
            // nada que hacer después
        }

    }
}