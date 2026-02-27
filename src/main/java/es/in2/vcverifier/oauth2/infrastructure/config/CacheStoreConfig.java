package es.in2.vcverifier.oauth2.infrastructure.config;

import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationCodeData;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationRequestJWT;
import es.in2.vcverifier.oauth2.domain.model.RefreshTokenDataCache;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static es.in2.vcverifier.shared.domain.util.Constants.*;

@Configuration
@RequiredArgsConstructor
public class CacheStoreConfig {

    @Bean
    public CacheStore<String> cacheForNonceByState() {
        return new CacheStore<>(10, TimeUnit.MINUTES);
    }

    @Bean
    public CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT() {
        return new CacheStore<>(
                Long.parseLong(LOGIN_TIMEOUT),
                TimeUnit.of(ChronoUnit.valueOf(LOGIN_TIMEOUT_CHRONO_UNIT)));
    }

    @Bean
    public CacheStore<RefreshTokenDataCache> cacheStoreForRefreshTokenData() {
        return new CacheStore<>(
                Long.parseLong(ACCESS_TOKEN_EXPIRATION_TIME),
                TimeUnit.of(ChronoUnit.valueOf(ACCESS_TOKEN_EXPIRATION_CHRONO_UNIT)));
    }

    @Bean
    public CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest() {
        return new CacheStore<>(10, TimeUnit.MINUTES);
    }

    @Bean
    public CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData() {
        return new CacheStore<>(10, TimeUnit.MINUTES);
    }

    @Bean
    public Set<String> jtiCache() {
        return new HashSet<>();
    }
    
    @Bean
    public Set<String> allowedClientsOrigins() {
        return Collections.synchronizedSet(new HashSet<>());
    }

}
