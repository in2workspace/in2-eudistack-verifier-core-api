package es.in2.vcverifier.verifier.domain.model.dcql;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DcqlQueryTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @DisplayName("Serialize DCQL query with dc+sd-jwt format")
    void serialize_sdJwtFormat() throws Exception {
        DcqlQuery query = new DcqlQuery(List.of(
                new CredentialQuery(
                        "lear_sd_jwt",
                        CredentialQuery.FORMAT_DC_SD_JWT,
                        new CredentialQuery.CredentialMeta(
                                List.of("LEARCredentialEmployee"),
                                null
                        ),
                        null
                )
        ));

        String json = mapper.writeValueAsString(query);

        assertTrue(json.contains("\"format\":\"dc+sd-jwt\""));
        assertTrue(json.contains("\"vct_values\":[\"LEARCredentialEmployee\"]"));
        assertFalse(json.contains("credential_definition"));
    }

    @Test
    @DisplayName("Serialize DCQL query with jwt_vc_json format")
    void serialize_jwtVcJsonFormat() throws Exception {
        DcqlQuery query = new DcqlQuery(List.of(
                new CredentialQuery(
                        "lear_jwt_vc",
                        CredentialQuery.FORMAT_JWT_VC_JSON,
                        new CredentialQuery.CredentialMeta(
                                null,
                                new CredentialQuery.CredentialDefinition(
                                        List.of("VerifiableCredential", "LEARCredentialEmployee")
                                )
                        ),
                        null
                )
        ));

        String json = mapper.writeValueAsString(query);

        assertTrue(json.contains("\"format\":\"jwt_vc_json\""));
        assertTrue(json.contains("\"credential_definition\""));
        assertFalse(json.contains("vct_values"));
    }

    @Test
    @DisplayName("Serialize DCQL query with both formats")
    void serialize_bothFormats() throws Exception {
        DcqlQuery query = new DcqlQuery(List.of(
                new CredentialQuery(
                        "lear_sd_jwt",
                        CredentialQuery.FORMAT_DC_SD_JWT,
                        new CredentialQuery.CredentialMeta(List.of("LEARCredentialEmployee"), null),
                        null
                ),
                new CredentialQuery(
                        "lear_jwt_vc",
                        CredentialQuery.FORMAT_JWT_VC_JSON,
                        new CredentialQuery.CredentialMeta(
                                null,
                                new CredentialQuery.CredentialDefinition(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        ),
                        null
                )
        ));

        String json = mapper.writeValueAsString(query);
        DcqlQuery deserialized = mapper.readValue(json, DcqlQuery.class);

        assertEquals(2, deserialized.credentials().size());
        assertEquals("lear_sd_jwt", deserialized.credentials().get(0).id());
        assertEquals("lear_jwt_vc", deserialized.credentials().get(1).id());
    }

    @Test
    @DisplayName("Deserialize DCQL query round-trip")
    void deserialize_roundTrip() throws Exception {
        String json = """
                {
                  "credentials": [
                    {
                      "id": "test",
                      "format": "dc+sd-jwt",
                      "meta": {
                        "vct_values": ["LEARCredentialEmployee"]
                      },
                      "claims": [
                        { "path": ["credentialSubject", "mandate", "mandatee", "firstName"] }
                      ]
                    }
                  ]
                }
                """;

        DcqlQuery query = mapper.readValue(json, DcqlQuery.class);

        assertEquals(1, query.credentials().size());
        assertEquals("test", query.credentials().get(0).id());
        assertEquals("dc+sd-jwt", query.credentials().get(0).format());
        assertEquals(1, query.credentials().get(0).claims().size());
        assertEquals(List.of("credentialSubject", "mandate", "mandatee", "firstName"),
                query.credentials().get(0).claims().get(0).path());
    }

    @Test
    @DisplayName("Null optional fields are omitted in serialization")
    void serialize_nullFieldsOmitted() throws Exception {
        DcqlQuery query = new DcqlQuery(List.of(
                new CredentialQuery("test", "dc+sd-jwt", null, null)
        ));

        String json = mapper.writeValueAsString(query);

        assertFalse(json.contains("meta"));
        assertFalse(json.contains("claims"));
    }
}
