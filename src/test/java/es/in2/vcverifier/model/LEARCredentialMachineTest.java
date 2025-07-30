package es.in2.vcverifier.model;

import es.in2.vcverifier.model.credentials.Issuer;
import es.in2.vcverifier.model.credentials.lear.CredentialStatus;
import es.in2.vcverifier.model.credentials.lear.Mandator;
import es.in2.vcverifier.model.credentials.lear.machine.LEARCredentialMachine;
import es.in2.vcverifier.model.credentials.lear.machine.subject.CredentialSubject;
import es.in2.vcverifier.model.credentials.lear.machine.subject.mandate.Mandate;
import es.in2.vcverifier.model.credentials.lear.machine.subject.mandate.mandatee.Mandatee;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

class LEARCredentialMachineTest {

    @Test
    void shouldBuildLEARCredentialMachineAndAccessFieldsCorrectly() {
        // Mandatee
        Mandatee mandatee = Mandatee.builder()
                .id("mandatee-123")
                .serviceName("service-name")
                .build();

        // Mandator
        Mandator mandator = Mandator.builder()
                .organizationIdentifier("org-id-456")
                .organization("org-name")
                .build();

        // Mandate
        Mandate mandate = Mandate.builder()
                .id("mandate-id")
                .mandatee(mandatee)
                .mandator(mandator)
                .build();

        // CredentialSubject
        CredentialSubject subject = CredentialSubject.builder()
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
        LEARCredentialMachine credential = LEARCredentialMachine.builder()
                .id("vc-id")
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .context(List.of("https://example.org/context"))
                .credentialSubject(subject)
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
        Mandatee mandatee = Mandatee.builder().id("mandatee-123").build();
        Mandator mandator = Mandator.builder().organizationIdentifier("org-999").build();
        Mandate mandate = Mandate.builder().mandatee(mandatee).mandator(mandator).build();
        CredentialSubject subject = CredentialSubject.builder().mandate(mandate).build();
        Issuer issuer = () -> "did:example:issuer";

        LEARCredentialMachine credential = LEARCredentialMachine.builder()
                .credentialSubject(subject)
                .issuer(issuer)
                .credentialStatus(null)
                .build();

        assertThat(credential.learCredentialStatusExist()).isFalse();
    }
}

