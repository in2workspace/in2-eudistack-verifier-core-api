package es.in2.vcverifier.model;

import es.in2.vcverifier.model.credentials.lear.CredentialStatus;
import es.in2.vcverifier.model.credentials.lear.Mandator;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV1;
import es.in2.vcverifier.model.credentials.lear.employee.subject.CredentialSubjectV1;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.MandateV1;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.mandatee.MandateeV1;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LEARCredentialEmployeeV1Test {

    @Test
    void shouldBuildLEARCredentialEmployeeV1AndAccessFieldsCorrectly() {
        MandateeV1 mandatee = MandateeV1.builder()
                .id("mandatee-id-123")
                .firstName("John")
                .lastName("Doe")
                .email("john.doe@example.com")
                .build();

        Mandator mandator = Mandator.builder()
                .organizationIdentifier("org-456")
                .build();

        MandateV1 mandate = MandateV1.builder()
                .id("mandate-789")
                .mandatee(mandatee)
                .mandator(mandator)
                .build();

        CredentialSubjectV1 subject = CredentialSubjectV1.builder()
                .mandate(mandate)
                .build();

        CredentialStatus credentialStatus = CredentialStatus.builder()
                .id("status-id")
                .type("StatusType")
                .purpose("assertionMethod")
                .index("123")
                .credentials("https://statuslist.example.com/123")
                .build();

        LEARCredentialEmployeeV1 credential = LEARCredentialEmployeeV1.builder()
                .id("vc-id-001")
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .context(List.of("https://www.w3.org/2018/credentials/v1"))
                .credentialSubjectV1(subject)
                .credentialStatus(credentialStatus)
                .build();

        // Assertions
        assertEquals("mandatee-id-123", credential.mandateeId());
        assertEquals("org-456", credential.mandatorOrganizationIdentifier());
        assertTrue(credential.learCredentialStatusExist());
        assertEquals("status-id", credential.credentialStatusId());
        assertEquals("StatusType", credential.credentialStatusType());
        assertEquals("assertionMethod", credential.credentialStatusPurpose());
        assertEquals("123", credential.credentialStatusListIndex());
        assertEquals("https://statuslist.example.com/123", credential.statusListCredential());
        assertEquals("John", credential.mandateeFirstName());
        assertEquals("Doe", credential.mandateeLastName());
        assertEquals("john.doe@example.com", credential.mandateeEmail());
    }

    @Test
    void credentialSubjectId_shouldBeNull_forLegacyV1() {
        MandateeV1 mandatee = MandateeV1.builder()
                .id("mandatee-id-123")
                .firstName("John")
                .lastName("Doe")
                .email("john.doe@example.com")
                .build();

        Mandator mandator = Mandator.builder()
                .organizationIdentifier("org-456")
                .build();

        MandateV1 mandate = MandateV1.builder()
                .id("mandate-789")
                .mandatee(mandatee)
                .mandator(mandator)
                .build();

        CredentialSubjectV1 subject = CredentialSubjectV1.builder()
                .mandate(mandate)
                .build();

        LEARCredentialEmployeeV1 credential = LEARCredentialEmployeeV1.builder()
                .id("vc-id-001")
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .context(List.of("https://www.w3.org/2018/credentials/v1"))
                .credentialSubjectV1(subject)
                .build();

        assertEquals(null, credential.credentialSubjectId());
    }


}
