package es.in2.vcverifier.model;

import es.in2.vcverifier.model.credentials.lear.CredentialStatus;
import es.in2.vcverifier.model.credentials.lear.Mandator;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV2;
import es.in2.vcverifier.model.credentials.lear.employee.subject.CredentialSubjectV2;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.MandateV2;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.mandatee.MandateeV2;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class LEARCredentialEmployeeV2Test {

    @Test
    void learCredentialEmployeeV2_shouldReturnExpectedValues() {
        // Arrange
        MandateeV2 mandatee = MandateeV2.builder()
                .id("emp-123")
                .firstName("Alice")
                .lastName("Smith")
                .email("alice.smith@example.com")
                .build();

        Mandator mandator = Mandator.builder()
                .organizationIdentifier("org-999")
                .build();

        MandateV2 mandate = MandateV2.builder()
                .id("mandate-v2-001")
                .mandatee(mandatee)
                .mandator(mandator)
                .build();

        CredentialSubjectV2 credentialSubjectV2 = CredentialSubjectV2.builder()
                .mandate(mandate)
                .build();

        CredentialStatus credentialStatus = CredentialStatus.builder()
                .id("status-001")
                .type("StatusTypeV2")
                .purpose("assertionMethod")
                .index("45")
                .credentials("https://statuslist.example.com/45")
                .build();

        LEARCredentialEmployeeV2 credential = LEARCredentialEmployeeV2.builder()
                .id("vc-v2-employee-001")
                .context(List.of("https://www.w3.org/2018/credentials/v1"))
                .type(List.of("VerifiableCredential", "LEARCredentialEmployeeV2"))
                .description("Credential for employee V2")
                .credentialSubjectV2(credentialSubjectV2)
                .credentialStatus(credentialStatus)
                .build();

        // Act & Assert
        assertEquals("emp-123", credential.mandateeId());
        assertEquals("org-999", credential.mandatorOrganizationIdentifier());
        assertTrue(credential.learCredentialStatusExist());

        assertEquals("status-001", credential.credentialStatusId());
        assertEquals("StatusTypeV2", credential.credentialStatusType());
        assertEquals("assertionMethod", credential.credentialStatusPurpose());
        assertEquals("45", credential.credentialStatusListIndex());
        assertEquals("https://statuslist.example.com/45", credential.statusListCredential());

        assertEquals("Alice", credential.mandateeFirstName());
        assertEquals("Smith", credential.mandateeLastName());
        assertEquals("alice.smith@example.com", credential.mandateeEmail());
    }

    @Test
    void credentialSubjectId_shouldBeNull_forLegacyV1() {
        MandateeV2 mandatee = MandateeV2.builder()
                .id("mandatee-id-123")
                .firstName("John")
                .lastName("Doe")
                .email("john.doe@example.com")
                .build();

        Mandator mandator = Mandator.builder()
                .organizationIdentifier("org-456")
                .build();

        MandateV2 mandate = MandateV2.builder()
                .id("mandate-789")
                .mandatee(mandatee)
                .mandator(mandator)
                .build();

        CredentialSubjectV2 subject = CredentialSubjectV2.builder()
                .mandate(mandate)
                .build();

        LEARCredentialEmployeeV2 credential = LEARCredentialEmployeeV2.builder()
                .id("vc-id-001")
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .context(List.of("https://www.w3.org/2018/credentials/v1"))
                .credentialSubjectV2(subject)
                .build();

        // NEW: legacy V1 has no credentialSubject.id => must be null
        assertEquals(null, credential.credentialSubjectId());
    }



}
