package es.in2.vcverifier.verifier.domain.model.credentials;

import es.in2.vcverifier.verifier.domain.model.credentials.SimpleIssuer;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.machine.LEARCredentialMachineV2;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.machine.subject.CredentialSubjectV2;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.machine.subject.mandate.MandateV2;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.machine.subject.mandate.mandatee.MandateeV2;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LEARCredentialMachineV2Test {

    @Test
    void shouldBuildLEARCredentialMachineV2AndAccessFieldsCorrectly() {
        // Arrange
        MandateeV2 mandatee = MandateeV2.builder()
                .id("did:key:zMachine-123")
                .build();

        MandateV2 mandate = MandateV2.builder()
                .mandatee(mandatee)
                .build();

        CredentialSubjectV2 subject = CredentialSubjectV2.builder()
                .mandate(mandate)
                .build();

        LEARCredentialMachineV2 credential = LEARCredentialMachineV2.builder()
                .id("vc-id-001")
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .context(List.of("https://www.w3.org/2018/credentials/V2"))
                .issuer(SimpleIssuer.builder().id("did:elsi:issuer").build())
                .credentialSubjectV2(subject)
                .validFrom("2025-01-01T00:00:00Z")
                .validUntil("2030-01-01T00:00:00Z")
                .build();

        // Assert (legacy binding via mandatee.id)
        assertEquals("did:key:zMachine-123", credential.mandateeId());

        assertFalse(credential.learCredentialStatusExist());

        assertNull(credential.credentialSubjectId());
    }

    @Test
    void credentialSubjectId_shouldBeNull_forLegacyV2() {
        MandateeV2 mandatee = MandateeV2.builder()
                .id("did:key:zMachine-legacy")
                .build();

        MandateV2 mandate = MandateV2.builder()
                .mandatee(mandatee)
                .build();

        CredentialSubjectV2 subject = CredentialSubjectV2.builder()
                .mandate(mandate)
                .build();

        LEARCredentialMachineV2 credential = LEARCredentialMachineV2.builder()
                .id("vc-id-legacy")
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .context(List.of("https://www.w3.org/2018/credentials/V2"))
                .issuer(SimpleIssuer.builder().id("did:elsi:issuer").build())
                .credentialSubjectV2(subject)
                .build();

        // Assert
        assertNull(credential.credentialSubjectId());
        assertEquals("did:key:zMachine-legacy", credential.mandateeId());
    }
}
