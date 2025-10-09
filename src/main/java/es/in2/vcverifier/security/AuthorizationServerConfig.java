package es.in2.vcverifier.security;

import static es.in2.vcverifier.util.Constants.IS_NONCE_REQUIRED_ON_FAPI_PROFILE;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import es.in2.vcverifier.component.CryptoComponent;
import es.in2.vcverifier.config.BackendConfig;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.model.AuthorizationCodeData;
import es.in2.vcverifier.model.AuthorizationRequestJWT;
import es.in2.vcverifier.model.RefreshTokenDataCache;
import es.in2.vcverifier.security.filters.CustomAuthenticationProvider;
import es.in2.vcverifier.security.filters.CustomAuthorizationRequestConverter;
import es.in2.vcverifier.security.filters.CustomErrorResponseHandler;
import es.in2.vcverifier.security.filters.CustomTokenRequestConverter;
import es.in2.vcverifier.service.ClientAssertionValidationService;
import es.in2.vcverifier.service.DIDService;
import es.in2.vcverifier.service.JWTService;
import es.in2.vcverifier.service.VpService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final CryptoComponent cryptoComponent;
    private final DIDService didService;
    private final JWTService jwtService;
    private final ClientAssertionValidationService clientAssertionValidationService;
    private final VpService vpService;
    private final CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;
    private final CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    private final BackendConfig backendConfig;
    private final RegisteredClientRepository registeredClientRepository;
    private final CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;
    private final ObjectMapper objectMapper;
    private final RegisteredClientsCorsConfig registeredClientsCorsConfig;
    private final CacheStore<RefreshTokenDataCache> refreshTokenDataCacheCacheStore;
    private final CacheStore<String> cacheForNonceByState;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http
                .cors(cors -> cors.configurationSource(registeredClientsCorsConfig.registeredClientsCorsConfigurationSource()))
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint
                                // Adds an AuthenticationConverter (pre-processor) used when attempting to extract
                                // an OAuth2 authorization request (or consent) from HttpServletRequest to an instance
                                // of OAuth2AuthorizationCodeRequestAuthenticationToken or OAuth2AuthorizationConsentAuthenticationToken.
                                .authorizationRequestConverter(new CustomAuthorizationRequestConverter(didService,jwtService,cryptoComponent,cacheStoreForAuthorizationRequestJWT,cacheStoreForOAuth2AuthorizationRequest,backendConfig,registeredClientRepository, IS_NONCE_REQUIRED_ON_FAPI_PROFILE,cacheForNonceByState))
                                .errorResponseHandler(new CustomErrorResponseHandler())
                )
                .tokenEndpoint(tokenEndpoint ->
                        tokenEndpoint
                                .accessTokenRequestConverter(new CustomTokenRequestConverter(jwtService, clientAssertionValidationService, vpService, cacheStoreForAuthorizationCodeData,objectMapper, refreshTokenDataCacheCacheStore))
                                .authenticationProvider(new CustomAuthenticationProvider(jwtService,registeredClientRepository,backendConfig,objectMapper, refreshTokenDataCacheCacheStore, oAuth2AuthorizationService(), cacheStoreForAuthorizationCodeData))
                )
                .oidc(Customizer.withDefaults());    // Enable OpenID Connect 1.0
        return http.build();
    }
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        JWKSet jwkSet = new JWKSet(cryptoComponent.getECKey());
        return ( jwkSelector, context ) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
        OAuth2TokenValidator<Jwt> audienceValidator = new JwtClaimValidator<>(
                "aud", backendConfig.getUrl()::equals);
        OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(audienceValidator);
        jwtDecoder.setJwtValidator(withAudience);
        return jwtDecoder;
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getJwsHeader().algorithm(SignatureAlgorithm.ES256);
            }
        };
    }

    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }



    // Customiza los endpoint del Authorization Server
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(backendConfig.getUrl())
                .authorizationEndpoint("/oidc/authorize")
                .deviceAuthorizationEndpoint("/oidc/device_authorization")
                .deviceVerificationEndpoint("/oidc/device_verification")
                .tokenEndpoint("/oidc/token")
                .tokenIntrospectionEndpoint("/oidc/introspect")
                .tokenRevocationEndpoint("/oidc/revoke")
                .jwkSetEndpoint("/oidc/jwks")
                .oidcLogoutEndpoint("/oidc/logout")
                .oidcUserInfoEndpoint("/oidc/userinfo")
                .oidcClientRegistrationEndpoint("/oidc/register")
                .build();
    }

}
