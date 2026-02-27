package es.in2.vcverifier.oauth2.infrastructure.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class PublicCorsConfig {

    @Bean
    public CorsConfigurationSource publicCorsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Configure public endpoints
        CorsConfiguration publicConfig = new CorsConfiguration();
        publicConfig.setAllowedOriginPatterns(List.of("*")); //NOSONAR: CORS Config is intentional to allow access to all Wallets
        publicConfig.setAllowedMethods(List.of("GET", "POST"));
        publicConfig.setAllowedHeaders(List.of("Content-Type"));
        publicConfig.setAllowCredentials(false);
        source.registerCorsConfiguration("/health", publicConfig);
        source.registerCorsConfiguration("/oid4vp/auth-request/**", publicConfig);
        source.registerCorsConfiguration("/oid4vp/auth-response", publicConfig);
        source.registerCorsConfiguration("/api/login/**", publicConfig);
        return source;
    }
    
}
