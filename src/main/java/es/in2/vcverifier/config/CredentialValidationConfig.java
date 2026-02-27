package es.in2.vcverifier.config;

import es.in2.vcverifier.service.*;
import es.in2.vcverifier.service.impl.JsonSchemaCredentialValidator;
import es.in2.vcverifier.service.impl.LearCredentialClaimsExtractor;
import es.in2.vcverifier.service.impl.LocalSchemaResolver;
import es.in2.vcverifier.service.impl.SdJwtVerificationServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Slf4j
@Configuration
public class CredentialValidationConfig {

    @Bean
    public CredentialSchemaResolver localSchemaResolver() {
        log.info("Registering Local Schema Resolver");
        return new LocalSchemaResolver();
    }

    @Bean
    public CredentialValidator credentialValidator(List<CredentialSchemaResolver> resolvers) {
        log.info("Registering JSON Schema Credential Validator with {} resolvers", resolvers.size());
        return new JsonSchemaCredentialValidator(resolvers);
    }

    @Bean
    public ClaimsExtractor learCredentialClaimsExtractor() {
        log.info("Registering LEAR Credential Claims Extractor");
        return new LearCredentialClaimsExtractor();
    }

    @Bean
    public SdJwtVerificationService sdJwtVerificationService(DIDService didService, TrustFrameworkService trustFrameworkService) {
        log.info("Registering SD-JWT Verification Service");
        return new SdJwtVerificationServiceImpl(didService, trustFrameworkService);
    }
}
