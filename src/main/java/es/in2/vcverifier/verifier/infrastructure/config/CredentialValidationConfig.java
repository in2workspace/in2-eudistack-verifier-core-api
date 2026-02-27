package es.in2.vcverifier.verifier.infrastructure.config;

import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.verifier.domain.service.*;
import es.in2.vcverifier.shared.crypto.*;
import es.in2.vcverifier.verifier.infrastructure.adapter.schema.JsonSchemaCredentialValidator;
import es.in2.vcverifier.verifier.infrastructure.adapter.claims.LearCredentialClaimsExtractor;
import es.in2.vcverifier.verifier.infrastructure.adapter.schema.LocalSchemaResolver;
import es.in2.vcverifier.shared.crypto.SdJwtVerificationServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Slf4j
@Configuration
public class CredentialValidationConfig {

    @Bean
    public CredentialSchemaResolver localSchemaResolver(BackendConfig backendConfig) {
        log.info("Registering Local Schema Resolver");
        return new LocalSchemaResolver(backendConfig.getLocalSchemasDir());
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
