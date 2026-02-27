package es.in2.vcverifier.verifier.infrastructure.adapter.schema;
import es.in2.vcverifier.verifier.infrastructure.adapter.schema.LocalSchemaResolver;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.networknt.schema.JsonSchema;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class LocalSchemaResolverTest {

    private LocalSchemaResolver resolver;

    @BeforeEach
    void setUp() {
        resolver = new LocalSchemaResolver();
    }

    @Test
    void order_returns20() {
        assertEquals(20, resolver.order());
    }

    @Test
    void resolve_employeeV1Context_returnsSchema() {
        List<String> context = List.of(
                "https://www.w3.org/ns/credentials/v2",
                "https://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1"
        );
        Optional<JsonSchema> schema = resolver.resolve("LEARCredentialEmployee", context, JsonNodeFactory.instance.objectNode());
        assertTrue(schema.isPresent());
    }

    @Test
    void resolve_employeeV2Context_returnsSchema() {
        List<String> context = List.of(
                "https://www.w3.org/ns/credentials/v2",
                "https://www.dome-marketplace.eu/2025/credentials/learcredentialemployee/v2"
        );
        Optional<JsonSchema> schema = resolver.resolve("LEARCredentialEmployee", context, JsonNodeFactory.instance.objectNode());
        assertTrue(schema.isPresent());
    }

    @Test
    void resolve_employeeV3Context_returnsSchema() {
        List<String> context = List.of(
                "https://www.w3.org/ns/credentials/v2",
                "https://credentials.eudistack.eu/.well-known/credentials/lear_credential_employee/w3c/v3"
        );
        Optional<JsonSchema> schema = resolver.resolve("LEARCredentialEmployee", context, JsonNodeFactory.instance.objectNode());
        assertTrue(schema.isPresent());
    }

    @Test
    void resolve_machineWithoutSpecificContext_defaultsToV1() {
        List<String> context = List.of("https://www.w3.org/ns/credentials/v2");
        Optional<JsonSchema> schema = resolver.resolve("LEARCredentialMachine", context, JsonNodeFactory.instance.objectNode());
        assertTrue(schema.isPresent());
    }

    @Test
    void resolve_machineV2Context_returnsSchema() {
        List<String> context = List.of(
                "https://www.w3.org/ns/credentials/v2",
                "https://credentials.eudistack.eu/.well-known/credentials/lear_credential_machine/w3c/v2"
        );
        Optional<JsonSchema> schema = resolver.resolve("LEARCredentialMachine", context, JsonNodeFactory.instance.objectNode());
        assertTrue(schema.isPresent());
    }

    @Test
    void resolve_unknownType_returnsEmpty() {
        List<String> context = List.of("https://www.w3.org/ns/credentials/v2");
        Optional<JsonSchema> schema = resolver.resolve("SomeOtherCredential", context, JsonNodeFactory.instance.objectNode());
        assertTrue(schema.isEmpty());
    }

    @Test
    void resolve_cachedSchema_returnsSameInstance() {
        List<String> context = List.of(
                "https://www.w3.org/ns/credentials/v2",
                "https://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1"
        );
        ObjectNode node = JsonNodeFactory.instance.objectNode();
        Optional<JsonSchema> first = resolver.resolve("LEARCredentialEmployee", context, node);
        Optional<JsonSchema> second = resolver.resolve("LEARCredentialEmployee", context, node);

        assertTrue(first.isPresent());
        assertTrue(second.isPresent());
        assertSame(first.get(), second.get());
    }

    @Test
    void resolveVersion_employeeV1() {
        String version = LocalSchemaResolver.resolveVersion("LEARCredentialEmployee", List.of(
                "https://www.w3.org/ns/credentials/v2",
                "https://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1"
        ));
        assertEquals("v1", version);
    }

    @Test
    void resolveVersion_machineDefault() {
        String version = LocalSchemaResolver.resolveVersion("LEARCredentialMachine", List.of("https://www.w3.org/ns/credentials/v2"));
        assertEquals("v1", version);
    }

    @Test
    void resolveVersion_unknownType_returnsNull() {
        String version = LocalSchemaResolver.resolveVersion("UnknownType", List.of("https://www.w3.org/ns/credentials/v2"));
        assertNull(version);
    }

    @Test
    void resolveTypeName_employeeV1() {
        String type = LocalSchemaResolver.resolveTypeName("LEARCredentialEmployee", List.of(
                "https://www.w3.org/ns/credentials/v2",
                "https://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1"
        ));
        assertEquals("LEARCredentialEmployee", type);
    }

    @Test
    void resolveTypeName_unknownType_returnsSameInput() {
        String type = LocalSchemaResolver.resolveTypeName("UnknownType", List.of("https://www.w3.org/ns/credentials/v2"));
        assertEquals("UnknownType", type);
    }
}
