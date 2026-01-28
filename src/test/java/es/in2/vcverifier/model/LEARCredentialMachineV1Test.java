package es.in2.vcverifier.model;

import es.in2.vcverifier.model.credentials.SimpleIssuer;
import es.in2.vcverifier.model.credentials.lear.Mandator;
import es.in2.vcverifier.model.credentials.lear.machine.LEARCredentialMachineV1;
import es.in2.vcverifier.model.credentials.lear.machine.subject.CredentialSubjectV1;
import es.in2.vcverifier.model.credentials.lear.machine.subject.mandate.MandateV1;
import es.in2.vcverifier.model.credentials.lear.machine.subject.mandate.mandatee.MandateeV1;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LEARCredentialMachineV1Test {

    @Test
    void shouldBuildLEARCredentialMachineV1AndAccessFieldsCorrectly() {
        // Arrange
        MandateeV1 mandatee = MandateeV1.builder()
                .id("did:key:zMachine-123")
                .build();

        Mandator mandator = Mandator.builder()
                .organizationIdentifier("org-456")
                .build();

        MandateV1 mandate = MandateV1.builder()
                .mandatee(mandatee)
                .mandator(mandator)
                .build();

        CredentialSubjectV1 subject = CredentialSubjectV1.builder()
                .mandate(mandate)
                .build();

        LEARCredentialMachineV1 credential = LEARCredentialMachineV1.builder()
                .id("vc-id-001")
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .context(List.of("https://www.w3.org/2018/credentials/v1"))
                .issuer(SimpleIssuer.builder().id("did:elsi:issuer").build())
                .credentialSubjectV1(subject)
                .validFrom("2025-01-01T00:00:00Z")
                .validUntil("2030-01-01T00:00:00Z")
                .build();

        // Assert (legacy binding via mandatee.id)
        assertEquals("did:key:zMachine-123", credential.mandateeId());
        assertEquals("org-456", credential.mandatorOrganizationIdentifier());

        assertFalse(credential.learCredentialStatusExist());

        assertNull(credential.credentialSubjectId());
    }

    @Test
    void credentialSubjectId_shouldBeNull_forLegacyV1() {
        MandateeV1 mandatee = MandateeV1.builder()
                .id("did:key:zMachine-legacy")
                .build();

        MandateV1 mandate = MandateV1.builder()
                .mandatee(mandatee)
                .build();

        CredentialSubjectV1 subject = CredentialSubjectV1.builder()
                .mandate(mandate)
                .build();

        LEARCredentialMachineV1 credential = LEARCredentialMachineV1.builder()
                .id("vc-id-legacy")
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .context(List.of("https://www.w3.org/2018/credentials/v1"))
                .issuer(SimpleIssuer.builder().id("did:elsi:issuer").build())
                .credentialSubjectV1(subject)
                .build();

        // Assert
        assertNull(credential.credentialSubjectId());
        assertEquals("did:key:zMachine-legacy", credential.mandateeId());
    }
}
