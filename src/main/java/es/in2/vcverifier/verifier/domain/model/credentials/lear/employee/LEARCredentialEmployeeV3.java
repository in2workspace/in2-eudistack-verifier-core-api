package es.in2.vcverifier.verifier.domain.model.credentials.lear.employee;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import es.in2.vcverifier.verifier.domain.model.credentials.Issuer;
import es.in2.vcverifier.verifier.domain.model.credentials.IssuerDeserializer;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.CredentialStatus;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.employee.subject.CredentialSubjectV3;
import lombok.Builder;

import java.util.List;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record LEARCredentialEmployeeV3(
        @JsonProperty("@context")
        List<String> context,
        @JsonProperty("id")
        String id,
        @JsonProperty("type")
        List<String> type,
        @JsonProperty("description")
        String description,
        @JsonProperty("issuer") @JsonDeserialize(using = IssuerDeserializer.class)
        Issuer issuer,
        @JsonProperty("credentialSubject")
        CredentialSubjectV3 credentialSubjectV3,
        @JsonProperty("validFrom")
        String validFrom,
        @JsonProperty("validUntil")
        String validUntil,
        @JsonProperty("credentialStatus")
        CredentialStatus credentialStatus

) implements LEARCredentialEmployee {

    @Override
    public String mandateeId() {
        return credentialSubjectV3.mandate().mandatee().id();
    }

    @Override
    public String mandatorOrganizationIdentifier() {
        return credentialSubjectV3.mandate().mandator().organizationIdentifier();
    }

    @Override
    public boolean learCredentialStatusExist() { return credentialStatus != null; }

    @Override
    public String mandateeFirstName() {
        return credentialSubjectV3.mandate().mandatee().firstName();
    }

    @Override
    public String mandateeLastName() {
        return credentialSubjectV3.mandate().mandatee().lastName();
    }

    @Override
    public String mandateeEmail() {
        return credentialSubjectV3.mandate().mandatee().email();
    }

    @Override
    public String credentialStatusId() { return credentialStatus.id(); }

    @Override
    public String credentialStatusType() { return credentialStatus.type(); }

    @Override
    public String credentialStatusPurpose() { return credentialStatus.purpose(); }

    @Override
    public String credentialStatusListIndex() { return credentialStatus.index(); }

    @Override
    public String statusListCredential() { return credentialStatus.credentials(); }

    @Override
    public String credentialSubjectId() {
        return credentialSubjectV3 != null ? credentialSubjectV3.id() : null;
    }
}

