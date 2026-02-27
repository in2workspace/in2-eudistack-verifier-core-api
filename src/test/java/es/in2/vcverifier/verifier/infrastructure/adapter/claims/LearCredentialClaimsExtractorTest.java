package es.in2.vcverifier.verifier.infrastructure.adapter.claims;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;
import es.in2.vcverifier.verifier.infrastructure.adapter.claims.LearCredentialClaimsExtractor;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LearCredentialClaimsExtractorTest {

    private final LearCredentialClaimsExtractor extractor = new LearCredentialClaimsExtractor();

    @Test
    void supports_learCredentialEmployee_true() {
        assertTrue(extractor.supports("LEARCredentialEmployee"));
    }

    @Test
    void supports_learCredentialMachine_true() {
        assertTrue(extractor.supports("LEARCredentialMachine"));
    }

    @Test
    void supports_unknownType_false() {
        assertFalse(extractor.supports("SomeOtherType"));
    }

    @Test
    void extract_employeeV1_withSnakeCaseFields() {
        JsonNode vc = buildEmployeeWithSnakeCase("did:key:zSub1", "John", "Doe", "john@example.com");

        ExtractedClaims claims = extractor.extract(vc);

        assertEquals("did:key:zSub1", claims.subjectDid());
        assertEquals("VATES-12345678", claims.mandatorOrgId());
        assertEquals("did:elsi:VATES-12345678", claims.issuerDid());
        assertEquals("openid learcredential", claims.scope());
        assertEquals("John Doe", claims.idTokenClaims().get("name"));
        assertEquals("John", claims.idTokenClaims().get("given_name"));
        assertEquals("Doe", claims.idTokenClaims().get("family_name"));
        assertEquals("john@example.com", claims.idTokenClaims().get("email"));
        assertEquals(true, claims.idTokenClaims().get("email_verified"));
    }

    @Test
    void extract_employeeV3_withCamelCaseFields() {
        JsonNode vc = buildEmployeeWithCamelCase("did:key:zSub2", "Jane", "Smith", "jane@example.com");

        ExtractedClaims claims = extractor.extract(vc);

        assertEquals("did:key:zSub2", claims.subjectDid());
        assertEquals("Jane Smith", claims.idTokenClaims().get("name"));
        assertEquals("Jane", claims.idTokenClaims().get("given_name"));
        assertEquals("Smith", claims.idTokenClaims().get("family_name"));
    }

    @Test
    void extract_machine_noIdTokenClaims() {
        JsonNode vc = buildMachineCredential("did:key:zMachine1");

        ExtractedClaims claims = extractor.extract(vc);

        assertEquals("did:key:zMachine1", claims.subjectDid());
        assertEquals("VATES-12345678", claims.mandatorOrgId());
        assertEquals("machine learcredential", claims.scope());
        assertTrue(claims.idTokenClaims().isEmpty());
    }

    @Test
    void extract_subjectDid_fallsBackToMandateeId() {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("LEARCredentialEmployee");

        vc.putObject("issuer").put("id", "did:elsi:VATES-12345678");

        ObjectNode cs = vc.putObject("credentialSubject");
        // No "id" on credentialSubject
        ObjectNode mandate = cs.putObject("mandate");
        ObjectNode mandatee = mandate.putObject("mandatee");
        mandatee.put("id", "did:key:zFromMandatee");
        mandatee.put("firstName", "Test");
        mandatee.put("lastName", "User");
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");
        mandate.putArray("power");

        ExtractedClaims claims = extractor.extract(vc);

        assertEquals("did:key:zFromMandatee", claims.subjectDid());
    }

    @Test
    void extract_issuerAsString() {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("LEARCredentialMachine");

        // issuer as plain string
        vc.put("issuer", "did:elsi:VATES-STRING-ISSUER");

        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", "did:key:zMachine");
        ObjectNode mandate = cs.putObject("mandate");
        mandate.putObject("mandatee").put("id", "did:key:zMachine");
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");
        mandate.putArray("power");

        ExtractedClaims claims = extractor.extract(vc);

        assertEquals("did:elsi:VATES-STRING-ISSUER", claims.issuerDid());
    }

    // --- Helper methods ---

    private JsonNode buildEmployeeWithSnakeCase(String subjectDid, String firstName, String lastName, String email) {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("LEARCredentialEmployee");

        vc.putObject("issuer").put("id", "did:elsi:VATES-12345678");

        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", subjectDid);
        ObjectNode mandate = cs.putObject("mandate");
        ObjectNode mandatee = mandate.putObject("mandatee");
        mandatee.put("id", subjectDid);
        mandatee.put("first_name", firstName);
        mandatee.put("last_name", lastName);
        mandatee.put("email", email);
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");
        mandate.putArray("power");

        return vc;
    }

    private JsonNode buildEmployeeWithCamelCase(String subjectDid, String firstName, String lastName, String email) {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("LEARCredentialEmployee");

        vc.putObject("issuer").put("id", "did:elsi:VATES-12345678");

        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", subjectDid);
        ObjectNode mandate = cs.putObject("mandate");
        ObjectNode mandatee = mandate.putObject("mandatee");
        mandatee.put("id", subjectDid);
        mandatee.put("firstName", firstName);
        mandatee.put("lastName", lastName);
        mandatee.put("email", email);
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");
        mandate.putArray("power");

        return vc;
    }

    private JsonNode buildMachineCredential(String subjectDid) {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("LEARCredentialMachine");

        vc.putObject("issuer").put("id", "did:elsi:VATES-12345678");

        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", subjectDid);
        ObjectNode mandate = cs.putObject("mandate");
        mandate.putObject("mandatee").put("id", subjectDid);
        mandate.putObject("mandator").put("organizationIdentifier", "VATES-12345678");
        mandate.putArray("power");

        return vc;
    }
}
