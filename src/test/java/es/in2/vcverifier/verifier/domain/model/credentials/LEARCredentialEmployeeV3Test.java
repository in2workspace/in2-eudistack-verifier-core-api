package es.in2.vcverifier.verifier.domain.model.credentials;

import es.in2.vcverifier.verifier.domain.model.credentials.lear.CredentialStatus;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.employee.LEARCredentialEmployeeV3;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.employee.subject.CredentialSubjectV3;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.employee.subject.mandate.MandateV3;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.employee.subject.mandate.mandatee.MandateeV3;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LEARCredentialEmployeeV3Test {

    @Test
    void shouldBuildLEARCredentialEmployeeV3AndAccessFieldsCorrectly() {
        MandateeV3 mandatee = MandateeV3.builder()
                .id("mandatee-id-123")
                .firstName("John")
                .lastName("Doe")
                .email("john.doe@example.com")
                .build();

        MandateV3 mandate = MandateV3.builder()
                .mandatee(mandatee)
                .build();

        CredentialSubjectV3 subject = CredentialSubjectV3.builder()
                .mandate(mandate)
                .build();

        CredentialStatus credentialStatus = CredentialStatus.builder()
                .id("status-id")
                .type("StatusType")
                .purpose("assertionMethod")
                .index("123")
                .credentials("https://statuslist.example.com/123")
                .build();

        LEARCredentialEmployeeV3 credential = LEARCredentialEmployeeV3.builder()
                .id("vc-id-001")
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .context(List.of("https://www.w3.org/2018/credentials/V3"))
                .credentialSubjectV3(subject)
                .credentialStatus(credentialStatus)
                .build();

        // Assertions
        assertEquals("mandatee-id-123", credential.mandateeId());
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
    void credentialSubjectId_shouldBeNull_forLegacyV3() {
        MandateeV3 mandatee = MandateeV3.builder()
                .id("mandatee-id-123")
                .firstName("John")
                .lastName("Doe")
                .email("john.doe@example.com")
                .build();

        MandateV3 mandate = MandateV3.builder()
                .mandatee(mandatee)
                .build();

        CredentialSubjectV3 subject = CredentialSubjectV3.builder()
                .mandate(mandate)
                .build();

        LEARCredentialEmployeeV3 credential = LEARCredentialEmployeeV3.builder()
                .id("vc-id-001")
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .context(List.of("https://www.w3.org/2018/credentials/V3"))
                .credentialSubjectV3(subject)
                .build();

        assertEquals(null, credential.credentialSubjectId());
    }


}
