package es.in2.vcverifier.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.model.validation.ValidationResult;
import es.in2.vcverifier.service.impl.JsonSchemaCredentialValidator;
import es.in2.vcverifier.service.impl.LocalSchemaResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JsonSchemaCredentialValidatorTest {

    private JsonSchemaCredentialValidator validator;

    @BeforeEach
    void setUp() {
        LocalSchemaResolver resolver = new LocalSchemaResolver();
        validator = new JsonSchemaCredentialValidator(List.of(resolver));
    }

    @Test
    void validate_validEmployeeV1Credential_success() {
        JsonNode credential = buildEmployeeV1();

        ValidationResult result = validator.validate(credential);

        assertTrue(result.valid());
        assertEquals("LEARCredentialEmployee", result.credentialType());
        assertTrue(result.errors().isEmpty());
    }

    @Test
    void validate_validMachineV1Credential_success() {
        JsonNode credential = buildMachineV1();

        ValidationResult result = validator.validate(credential);

        assertTrue(result.valid());
        assertEquals("LEARCredentialMachine", result.credentialType());
        assertTrue(result.errors().isEmpty());
    }

    @Test
    void validate_employeeMissingMandatee_fails() {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode context = vc.putArray("@context");
        context.add("https://www.w3.org/ns/credentials/v2");
        context.add("https://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1");

        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("LEARCredentialEmployee");

        vc.putObject("issuer").put("id", "did:elsi:VATES-12345678");
        // credentialSubject.mandate without mandatee
        ObjectNode cs = vc.putObject("credentialSubject");
        ObjectNode mandate = cs.putObject("mandate");
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");
        mandate.putArray("power");

        ValidationResult result = validator.validate(vc);

        assertFalse(result.valid());
        assertFalse(result.errors().isEmpty());
    }

    @Test
    void validate_unknownCredentialType_passesWithoutSchema() {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        vc.putArray("@context").add("https://www.w3.org/ns/credentials/v2");

        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("SomeNewCredentialType");

        ValidationResult result = validator.validate(vc);

        // No schema found for unknown type, should pass through
        assertTrue(result.valid());
        assertEquals("SomeNewCredentialType", result.credentialType());
    }

    @Test
    void validate_validEmployeeV3Credential_success() {
        JsonNode credential = buildEmployeeV3();

        ValidationResult result = validator.validate(credential);

        assertTrue(result.valid());
        assertEquals("LEARCredentialEmployee", result.credentialType());
    }

    // --- Helper methods ---

    private JsonNode buildEmployeeV1() {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode context = vc.putArray("@context");
        context.add("https://www.w3.org/ns/credentials/v2");
        context.add("https://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1");

        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("LEARCredentialEmployee");

        vc.putObject("issuer").put("id", "did:elsi:VATES-12345678");
        vc.put("validFrom", "2024-01-01T00:00:00Z");
        vc.put("validUntil", "2025-01-01T00:00:00Z");

        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", "did:key:zDnaeTest123");
        ObjectNode mandate = cs.putObject("mandate");
        ObjectNode mandatee = mandate.putObject("mandatee");
        mandatee.put("id", "did:key:zDnaeTest123");
        mandatee.put("first_name", "John");
        mandatee.put("last_name", "Doe");
        mandatee.put("email", "john@example.com");
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");
        mandate.putArray("power");

        return vc;
    }

    private JsonNode buildEmployeeV3() {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode context = vc.putArray("@context");
        context.add("https://www.w3.org/ns/credentials/v2");
        context.add("https://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v3");

        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("LEARCredentialEmployee");

        vc.putObject("issuer").put("id", "did:elsi:VATES-12345678");

        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", "did:key:zDnaeTest456");
        ObjectNode mandate = cs.putObject("mandate");
        ObjectNode mandatee = mandate.putObject("mandatee");
        mandatee.put("id", "did:key:zDnaeTest456");
        mandatee.put("firstName", "Jane");
        mandatee.put("lastName", "Smith");
        mandatee.put("email", "jane@example.com");
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");
        mandate.putArray("power");

        return vc;
    }

    private JsonNode buildMachineV1() {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode context = vc.putArray("@context");
        context.add("https://www.w3.org/ns/credentials/v2");

        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("LEARCredentialMachine");

        vc.putObject("issuer").put("id", "did:elsi:VATES-12345678");

        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", "did:key:zDnaeMachine123");
        ObjectNode mandate = cs.putObject("mandate");
        mandate.putObject("mandatee").put("id", "did:key:zDnaeMachine123");
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");
        mandate.putArray("power");

        return vc;
    }
}
