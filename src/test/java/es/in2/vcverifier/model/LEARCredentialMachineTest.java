package es.in2.vcverifier.model;

import es.in2.vcverifier.model.credentials.Issuer;
import es.in2.vcverifier.model.credentials.lear.CredentialStatus;
import es.in2.vcverifier.model.credentials.lear.Mandator;
import es.in2.vcverifier.model.credentials.lear.machine.LEARCredentialMachineV1;
import es.in2.vcverifier.model.credentials.lear.machine.subject.CredentialSubjectV1;
import es.in2.vcverifier.model.credentials.lear.machine.subject.mandate.MandateV1;
import es.in2.vcverifier.model.credentials.lear.machine.subject.mandate.mandatee.MandateeV1;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

class LEARCredentialMachineTest {

    @Test
    void shouldBuildLEARCredentialMachineAndAccessFieldsCorrectly() {
        // Mandatee
        MandateeV1 mandatee = MandateeV1.builder()
                .id("mandatee-123")
                .serviceName("service-name")
                .build();

        // Mandator
        Mandator mandator = Mandator.builder()
                .organizationIdentifier("org-id-456")
                .organization("org-name")
                .build();

        // Mandate
        MandateV1 mandate = es.in2.vcverifier.model.credentials.lear.machine.subject.mandate.MandateV1.builder()
                .id("mandate-id")
                .mandatee(mandatee)
                .mandator(mandator)
                .build();

        // CredentialSubject
        CredentialSubjectV1 subject = CredentialSubjectV1.builder()
                .mandate(mandate)
                .build();

        // CredentialStatus
        CredentialStatus status = CredentialStatus.builder()
                .id("status-id")
                .type("StatusList2021Entry")
                .purpose("revocation")
                .index("42")
                .credentials("https://example.com/status-list")
                .build();

        // Issuer implementation (record is not, but interface is used)
        Issuer issuer = () -> "did:example:issuer";

        // LEARCredentialMachine
        LEARCredentialMachineV1 credential = LEARCredentialMachineV1.builder()
                .id("vc-id")
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .context(List.of("https://example.org/context"))
                .credentialSubjectV1(subject)
                .credentialStatus(status)
                .issuer(issuer)
                .issuanceDate("2024-01-01T00:00:00Z")
                .expirationDate("2025-01-01T00:00:00Z")
                .validFrom("2024-01-01T00:00:00Z")
                .validUntil("2025-01-01T00:00:00Z")
                .build();

        // Verificaciones
        assertThat(credential.mandateeId()).isEqualTo("mandatee-123");
        assertThat(credential.mandatorOrganizationIdentifier()).isEqualTo("org-id-456");

        assertThat(credential.learCredentialStatusExist()).isTrue();
        assertThat(credential.credentialStatusId()).isEqualTo("status-id");
        assertThat(credential.credentialStatusType()).isEqualTo("StatusList2021Entry");
        assertThat(credential.credentialStatusPurpose()).isEqualTo("revocation");
        assertThat(credential.credentialStatusListIndex()).isEqualTo("42");
        assertThat(credential.statusListCredential()).isEqualTo("https://example.com/status-list");
    }

    @Test
    void shouldHandleNullCredentialStatusGracefully() {
        MandateeV1 mandatee = MandateeV1.builder().id("mandatee-123").build();
        Mandator mandator = Mandator.builder().organizationIdentifier("org-999").build();
        es.in2.vcverifier.model.credentials.lear.machine.subject.mandate.MandateV1 mandate = es.in2.vcverifier.model.credentials.lear.machine.subject.mandate.MandateV1.builder().mandatee(mandatee).mandator(mandator).build();
        CredentialSubjectV1 subject = CredentialSubjectV1.builder().mandate(mandate).build();
        Issuer issuer = () -> "did:example:issuer";

        LEARCredentialMachineV1 credential = LEARCredentialMachineV1.builder()
                .credentialSubjectV1(subject)
                .issuer(issuer)
                .credentialStatus(null)
                .build();

        assertThat(credential.learCredentialStatusExist()).isFalse();
    }
}

