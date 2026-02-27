package es.in2.vcverifier.verifier.domain.model.credentials.lear.employee;

import es.in2.vcverifier.verifier.domain.model.credentials.lear.LEARCredential;

public interface LEARCredentialEmployee extends LEARCredential {
    String mandateeFirstName();
    String mandateeLastName();
    String mandateeEmail();
}
