package es.in2.vcverifier.verifier.infrastructure.adapter.schema;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SpecVersion;
import es.in2.vcverifier.verifier.domain.service.CredentialSchemaResolver;
import lombok.extern.slf4j.Slf4j;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves JSON Schemas from local resources.
 * If an external schemas directory is configured, reads from there;
 * otherwise falls back to classpath resources.
 * Schemas are expected as: {credentialType}.{version}.json
 * <p>
 * Context-to-version mapping is maintained internally.
 */
@Slf4j
public class LocalSchemaResolver implements CredentialSchemaResolver {

    private static final String CLASSPATH_SCHEMA_BASE = "schemas/";
    private final Map<String, JsonSchema> cache = new ConcurrentHashMap<>();
    private final String externalSchemasDir;

    public LocalSchemaResolver() {
        this(null);
    }

    public LocalSchemaResolver(String externalSchemasDir) {
        this.externalSchemasDir = externalSchemasDir;
    }

    // Context URL -> (credentialType, version) mapping
    private static final Map<String, CredentialTypeVersion> CONTEXT_MAP = Map.of(
            "https://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1",
            new CredentialTypeVersion("LEARCredentialEmployee", "v1"),

            "https://www.dome-marketplace.eu/2025/credentials/learcredentialemployee/v2",
            new CredentialTypeVersion("LEARCredentialEmployee", "v2"),

            "https://credentials.eudistack.eu/.well-known/credentials/lear_credential_employee/w3c/v3",
            new CredentialTypeVersion("LEARCredentialEmployee", "v3"),

            "https://credentials.eudistack.eu/.well-known/credentials/lear_credential_machine/w3c/v2",
            new CredentialTypeVersion("LEARCredentialMachine", "v2")
    );

    // Default version for machine credentials without a specific context
    private static final CredentialTypeVersion MACHINE_V1_DEFAULT =
            new CredentialTypeVersion("LEARCredentialMachine", "v1");

    private record CredentialTypeVersion(String type, String version) {}

    @Override
    public int order() {
        return 20;
    }

    @Override
    public Optional<JsonSchema> resolve(String credentialType, List<String> context, JsonNode credential) {
        CredentialTypeVersion typeVersion = resolveTypeVersion(credentialType, context);
        if (typeVersion == null) {
            log.debug("No local schema mapping found for type={}, context={}", credentialType, context);
            return Optional.empty();
        }

        String schemaFileName = typeVersion.type() + "." + typeVersion.version() + ".json";
        return Optional.ofNullable(cache.computeIfAbsent(schemaFileName, this::loadSchema));
    }

    /**
     * Returns the credential type and version string resolved from a context list.
     */
    public static String resolveVersion(String credentialType, List<String> context) {
        CredentialTypeVersion tv = resolveTypeVersionStatic(credentialType, context);
        return tv != null ? tv.version() : null;
    }

    /**
     * Returns the resolved credential type name from context.
     */
    public static String resolveTypeName(String credentialType, List<String> context) {
        CredentialTypeVersion tv = resolveTypeVersionStatic(credentialType, context);
        return tv != null ? tv.type() : credentialType;
    }

    private CredentialTypeVersion resolveTypeVersion(String credentialType, List<String> context) {
        return resolveTypeVersionStatic(credentialType, context);
    }

    private static CredentialTypeVersion resolveTypeVersionStatic(String credentialType, List<String> context) {
        for (String ctx : context) {
            CredentialTypeVersion tv = CONTEXT_MAP.get(ctx);
            if (tv != null) {
                return tv;
            }
        }
        // Default: machine V1 if credentialType is machine and no specific context
        if ("LEARCredentialMachine".equals(credentialType)) {
            return MACHINE_V1_DEFAULT;
        }
        return null;
    }

    private JsonSchema loadSchema(String schemaFileName) {
        // Try external directory first
        if (externalSchemasDir != null && !externalSchemasDir.isBlank()) {
            Path externalFile = Path.of(externalSchemasDir, schemaFileName);
            if (Files.exists(externalFile)) {
                try (InputStream is = new FileInputStream(externalFile.toFile())) {
                    JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012);
                    JsonSchema schema = factory.getSchema(is, new com.networknt.schema.SchemaValidatorsConfig.Builder().build());
                    log.info("Loaded JSON Schema from external file: {}", externalFile);
                    return schema;
                } catch (Exception e) {
                    log.error("Failed to load JSON Schema from external file {}: {}", externalFile, e.getMessage());
                    // Fall through to classpath
                }
            }
        }

        // Fallback to classpath
        String classpathPath = CLASSPATH_SCHEMA_BASE + schemaFileName;
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(classpathPath)) {
            if (is == null) {
                log.warn("Schema not found on classpath: {}", classpathPath);
                return null;
            }
            JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012);
            JsonSchema schema = factory.getSchema(SchemaLocation.of("classpath:" + classpathPath), new com.networknt.schema.SchemaValidatorsConfig.Builder().build());
            log.info("Loaded JSON Schema from classpath: {}", classpathPath);
            return schema;
        } catch (Exception e) {
            log.error("Failed to load JSON Schema from {}: {}", classpathPath, e.getMessage());
            return null;
        }
    }
}
