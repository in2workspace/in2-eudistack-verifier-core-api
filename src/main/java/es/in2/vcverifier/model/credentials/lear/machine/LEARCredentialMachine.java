package es.in2.vcverifier.model.credentials.lear.machine;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import es.in2.vcverifier.model.credentials.Issuer;
import es.in2.vcverifier.model.credentials.IssuerDeserializer;
import es.in2.vcverifier.model.credentials.lear.CredentialStatus;
import es.in2.vcverifier.model.credentials.lear.LEARCredential;
import es.in2.vcverifier.model.credentials.lear.machine.subject.CredentialSubject;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

@Slf4j
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public record LEARCredentialMachine(
        @JsonProperty("@context")
        List<String> context,
        @JsonProperty("id")
        String id,
        @JsonProperty("type")
        List<String> type,
        @JsonProperty("issuer") @JsonDeserialize(using = IssuerDeserializer.class)
        Issuer issuer,
        @JsonProperty("credentialSubject")
        CredentialSubject credentialSubject,
        @JsonProperty("validFrom")
        String validFrom,
        @JsonProperty("validUntil")
        String validUntil,
        @JsonProperty("expirationDate")
        String expirationDate,
        @JsonProperty("issuanceDate")
        String issuanceDate,
        @JsonProperty("credentialStatus")
        CredentialStatus credentialStatus

) implements LEARCredential {

    @Override
    public String mandateeId() {
        return credentialSubject.mandate().mandatee().id();
    }

    @Override
    public String mandatorOrganizationIdentifier() {
        String orgId = null;
        try {
            orgId = credentialSubject.mandate().mandator().organizationIdentifier();
            if (orgId != null && !orgId.isBlank()) {
                log.debug("Trobada organizationIdentifier antiga: {}", orgId);
                return orgId.trim();
            } else {
                log.debug("organizationIdentifier antic nul o buit");
            }
        } catch (Exception e) {
            log.warn("Error intentant llegir organizationIdentifier antic", e);
        }

        String did = null;
        try {
            did = credentialSubject.mandate().mandator().id();
            if (did == null || did.isBlank()) {
                log.debug("mandator.id nul o buit");
                return "";
            }
            did = did.trim();
            log.debug("Llegit camp id (did): {}", did);
        } catch (Exception e) {
            log.warn("Error intentant llegir mandator.id", e);
            return "";
        }

        final String prefix = "did:elsi:";
        if (did.startsWith(prefix) && did.length() > prefix.length()) {
            String value = did.substring(prefix.length());
            log.debug("Extret de did: {} -> {}", did, value);
            return value;
        }

        int idx = did.lastIndexOf(':');
        if (idx >= 0 && idx < did.length() - 1) {
            String value = did.substring(idx + 1);
            log.debug("Extret de la darrera part de did: {} -> {}", did, value);
            return value;
        }

        log.debug("Retornant did tal qual: {}", did);
        return did;
    }



    @Override
    public boolean learCredentialStatusExist() { return credentialStatus != null; }

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

}
