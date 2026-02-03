package es.in2.vcverifier.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.shaded.gson.internal.LinkedTreeMap;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.exception.*;
import es.in2.vcverifier.model.credentials.SimpleIssuer;
import es.in2.vcverifier.model.credentials.lear.CredentialStatus;
import es.in2.vcverifier.model.credentials.lear.LEARCredential;
import es.in2.vcverifier.model.credentials.lear.Mandator;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV1;
import es.in2.vcverifier.model.credentials.lear.employee.subject.CredentialSubjectV1;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.MandateV1;
import es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.mandatee.MandateeV1;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.model.issuer.TimeRange;
import es.in2.vcverifier.service.impl.VpServiceImpl;
import org.assertj.core.api.Assertions;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static es.in2.vcverifier.util.Constants.DID_ELSI_PREFIX;
import static es.in2.vcverifier.util.Constants.LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VpServiceImplTest {

    @Mock
    private JWTService jwtService;

    @Mock
    private TrustFrameworkService trustFrameworkService;

    @Mock
    private DIDService didService;
    @Mock
    private CertificateValidationService certificateValidationService;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private VpServiceImpl vpServiceImpl;



    @Test
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_is_not_found_throws_CredentialException_and_return_false() {
        String vpClaimWithVcArrayEmpty = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbXX0sImV4cCI6MTcyMDAzMDAwMywiaWF0IjoxNzE3NDM4MDAzLCJqdGkiOiI0MWFjYWRhMy02N2I0LTQ5NGUtYTZlMy1lMDk2NjQ0OWYyNWQifQ.kR4ob7mBGb246EpUYpMRKaESEqGc7yZaNnyoZpkxbMrF_bgC9VLRmMagsHP4DXfl7f8XyBUKFyUcda2PUPs-bA";

        assertThrows(CredentialException.class, () ->
                vpServiceImpl.validateVerifiablePresentation(vpClaimWithVcArrayEmpty)
        );
    }

    @Test
    void validateVerifiablePresentation_vp_claim_with_verifiableCredential_claim_is_not_an_array_throws_CredentialException_and_return_false() {
        String vpClaimWithVcNotArrayFormat = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjoibm90LWFycmF5LWZvcm1hdCJ9LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0.0Jpm4g5IUBnZRH5Zf1FSs0nSJmdD9dQncchlFJoqT_tDU733rXLT7UbD0f4KIfwPPZn_APKNt-h5ziTQjgXJiw";

        assertThrows(CredentialException.class, () ->
                vpServiceImpl.validateVerifiablePresentation(vpClaimWithVcNotArrayFormat)
        );
    }

    @Test
    void validateVerifiablePresentation_vp_claim_without_verifiableCredential_claim_inside_throws_JWTClaimMissingException_and_return_false() {
        String vpClaimNotValidObject = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ2cCI6e319.hLaehswoW9QiU_FmLGCDZIPOvnNOvn2HsOCs9lKhHUE";

        assertThrows(JWTClaimMissingException.class, () ->
                vpServiceImpl.validateVerifiablePresentation(vpClaimNotValidObject)
        );
    }

    @Test
    void validateVerifiablePresentation_vp_claim_not_valid_object_throws_JWTClaimMissingException_and_return_false() {
        String vpClaimNotValidObject = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ2cCI6ImludmFsaWRWcEZvcm1hdCJ9.5-6R9OxqX7lXEEqVL_12Bf0UODXnkPtrt_ntoD2IrPQ";

        assertThrows(JWTClaimMissingException.class, () ->
                vpServiceImpl.validateVerifiablePresentation(vpClaimNotValidObject)
        );
    }

    @Test
    void validateVerifiablePresentation_invalidVP_throws_JWTClaimMissingException_and_return_false() {
        String jwtWithoutVpClaim = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        assertThrows(JWTClaimMissingException.class, () ->
                vpServiceImpl.validateVerifiablePresentation(jwtWithoutVpClaim)
        );
    }

    @Test
    void validateVerifiablePresentation_invalidVP_throws_JWTParsingException_and_return_false() {
        String invalidVP = "invalidVPJWT";

        assertThrows(JWTParsingException.class, () ->
                vpServiceImpl.validateVerifiablePresentation(invalidVP)
        );
    }

    @Test
    void mapPayloadToVerifiableCredential_whenVcObjectIsNotMap_shouldThrowCredentialMappingException() {
        String verifiablePresentation = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);

        when(jwtService.getVCFromPayload(payload)).thenReturn("not-a-map");

        assertThrows(
                CredentialMappingException.class,
                () ->  vpServiceImpl.validateVerifiablePresentation(verifiablePresentation)
        );
    }

    @Test
    void mapPayloadToVerifiableCredential_whenVcObjectIsMap_shouldThrowCredentialMappingException() {
        String verifiablePresentation = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);
        Map<Integer, Object> vcMap = new HashMap<>();
        vcMap.put(123, "test"); // incorrecto a propósito
        when(jwtService.getVCFromPayload(payload)).thenReturn(vcMap);

        assertThrows(
                CredentialMappingException.class,
                () ->  vpServiceImpl.validateVerifiablePresentation(verifiablePresentation)
        );
    }

    @Test
    void mapPayloadToVerifiableCredential_whenVcMapTypeObjectNotList_shouldThrowCredentialMappingException() {
        String verifiablePresentation = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);
        Map<String, Object> vcMap = new HashMap<>();
        vcMap.put("type", "not a list"); // incorrecto a propósito
        when(jwtService.getVCFromPayload(payload)).thenReturn(vcMap);

        assertThrows(
                CredentialMappingException.class,
                () ->  vpServiceImpl.validateVerifiablePresentation(verifiablePresentation)
        );
    }

    @Test
    void mapPayloadToVerifiableCredential_whenVcMapTypeObjectListHaveNotStrings_shouldThrowCredentialMappingException() {
        String verifiablePresentation = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);
        Map<String, Object> vcMap = new HashMap<>();
        vcMap.put("type", List.of(1,2)); // incorrecto a propósito
        when(jwtService.getVCFromPayload(payload)).thenReturn(vcMap);

        assertThrows(
                CredentialMappingException.class,
                () ->  vpServiceImpl.validateVerifiablePresentation(verifiablePresentation)
        );
    }

    @Test
    void mapPayloadToVerifiableCredential_whenMapToSpecificCredentialIncorrectTypes_shouldThrowInvalidCredentialTypeException() throws Exception {
        String vpToken = "vp.jwt";
        String vcJwt = "vc.jwt";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mocked = mockStatic(SignedJWT.class)) {
            mocked.when(() -> SignedJWT.parse(vpToken)).thenReturn(vpSignedJWT);
            mocked.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            // VP -> contains VC JWT in vp claim
            JWTClaimsSet vpClaims = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaims);
            when(vpClaims.getClaim("vp")).thenReturn(Map.of("verifiableCredential", List.of(vcJwt)));

            // VC sub is read (but not strictly needed for this test)
            JWTClaimsSet vcClaims = mock(JWTClaimsSet.class);
            when(vcSignedJWT.getJWTClaimsSet()).thenReturn(vcClaims);
            when(vcClaims.getSubject()).thenReturn("did:example:any");

            // Payload -> VC map
            Payload payload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(vcSignedJWT)).thenReturn(payload);

            Map<String, Object> vcMap = new HashMap<>();
            vcMap.put("type", List.of("invalid")); // unsupported type
            vcMap.put("@context", LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT); // must be a list of strings
            when(jwtService.getVCFromPayload(payload)).thenReturn(vcMap);

            assertThrows(
                    InvalidCredentialTypeException.class,
                    () -> vpServiceImpl.validateVerifiablePresentation(vpToken)
            );
        }
    }


    @Test
    void mapPayloadToVerifiableCredential_whenMapToSpecificCredentialBadContextNotList_shouldThrowCredentialMappingException() {
        String verifiablePresentation = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);
        Map<String, Object> vcMap = new HashMap<>();
        vcMap.put("type", List.of("LEARCredentialEmployee"));
        vcMap.put("@context", "not-a-list"); //worng on propouse

        when(jwtService.getVCFromPayload(payload)).thenReturn(vcMap);

        assertThrows(
                CredentialMappingException.class,
                () ->  vpServiceImpl.validateVerifiablePresentation(verifiablePresentation)
        );
    }

    @Test
    void mapPayloadToVerifiableCredential_whenMapToSpecificCredentialBadContextNotStringsElements_shouldThrowCredentialMappingException() {
        String verifiablePresentation = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);
        Map<String, Object> vcMap = new HashMap<>();
        vcMap.put("type", List.of("LEARCredentialEmployee"));
        vcMap.put("@context", List.of("https://example.com", 42));

        when(jwtService.getVCFromPayload(payload)).thenReturn(vcMap);

        assertThrows(
                CredentialMappingException.class,
                () ->  vpServiceImpl.validateVerifiablePresentation(verifiablePresentation)
        );
    }

    @Test
    void mapPayloadToVerifiableCredential_whenMapToSpecificCredentialNotContextList_shouldThrowInvalidCredentialTypeException() {
        String verifiablePresentation = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";

        Payload payload = mock(Payload.class);
        when(jwtService.getPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);
        Map<String, Object> vcMap = new HashMap<>();
        vcMap.put("type", List.of("LEARCredentialEmployee"));
        vcMap.put("@context", List.of());

        when(jwtService.getVCFromPayload(payload)).thenReturn(vcMap);

        assertThrows(
                InvalidCredentialTypeException.class,
                () ->  vpServiceImpl.validateVerifiablePresentation(verifiablePresentation)
        );
    }

    @Test
    void validateOldVerifiablePresentation_success() throws Exception {
        // Given
        String verifiablePresentation = "valid.vp.jwt";
        LEARCredentialEmployeeV1 learCredentialEmployeeV1 = getLEARCredentialEmployee();

        // Step 1: Parse the VP JWT
        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        try (MockedStatic<SignedJWT> mockedSignedJWT = mockStatic(SignedJWT.class)) {

            mockedSignedJWT.when(() -> SignedJWT.parse(verifiablePresentation)).thenReturn(vpSignedJWT);

            var vpHeader = mock(com.nimbusds.jose.JWSHeader.class);
            when(vpSignedJWT.getHeader()).thenReturn(vpHeader);
            when(vpHeader.getKeyID()).thenReturn(learCredentialEmployeeV1.mandateeId()); // holderDid

            // Set up the VP claims
            JWTClaimsSet vpClaimsSet = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaimsSet);

            // Mock the "vp" claim in the VP
            Map<String, Object> vcClaimMap = new HashMap<>();
            String vcJwt = "valid.vc.jwt";
            vcClaimMap.put("verifiableCredential", List.of(vcJwt));
            when(vpClaimsSet.getClaim("vp")).thenReturn(vcClaimMap);

            // Step 2: Parse the VC JWT
            SignedJWT jwtCredential = mock(SignedJWT.class);
            mockedSignedJWT.when(() -> SignedJWT.parse(vcJwt)).thenReturn(jwtCredential);

            // VC claims -> sub (binding source #2)
            JWTClaimsSet vcClaimsSet = mock(JWTClaimsSet.class);
            when(jwtCredential.getJWTClaimsSet()).thenReturn(vcClaimsSet);
            when(vcClaimsSet.getSubject()).thenReturn(learCredentialEmployeeV1.mandateeId());

            Payload payload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(jwtCredential)).thenReturn(payload);

            // Step 3: Validate the credential id is not in the revoked list
            // Create a vcFromPayload Map
            LinkedTreeMap<String, Object> vcFromPayload = new LinkedTreeMap<>();
            when(jwtService.getVCFromPayload(payload)).thenReturn(vcFromPayload);

            // Mock trustFrameworkService.getRevokedCredentialIds to return an empty list
            when(trustFrameworkService.getRevokedCredentialIds()).thenReturn(Collections.emptyList());

            // Step 4: Extract and validate credential types
            vcFromPayload.put("type", List.of("LEARCredentialEmployee"));
            vcFromPayload.put("@context", LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT);

            // Step 5: Retrieve the list of issuer capabilities
            List<IssuerCredentialsCapabilities> issuerCapabilitiesList = List.of(
                    IssuerCredentialsCapabilities.builder()
                            .validFor(new TimeRange(Instant.now().toString(), Instant.now().plusSeconds(3600).toString()))
                            .credentialsType("LEARCredentialEmployee")
                            .claims(null)
                            .build()
            );
            when(trustFrameworkService.getTrustedIssuerListData(learCredentialEmployeeV1.issuer().getId())).thenReturn(issuerCapabilitiesList);

            when(objectMapper.convertValue(vcFromPayload, LEARCredentialEmployeeV1.class)).thenReturn(learCredentialEmployeeV1);

            // Step 7: Validate the mandator with trusted issuer service
            when(trustFrameworkService.getTrustedIssuerListData(DID_ELSI_PREFIX + learCredentialEmployeeV1.mandatorOrganizationIdentifier())).thenReturn(issuerCapabilitiesList);

            // Step 7: Verify the signature and the organizationId of the credential signature
            Map<String, Object> vcHeader = new HashMap<>();
            vcHeader.put("x5c", List.of("base64Cert"));
            JWSHeader header = mock(JWSHeader.class);
            when(jwtCredential.getHeader()).thenReturn(header);
            when(header.toJSONObject()).thenReturn(vcHeader);


            when(jwtCredential.serialize()).thenReturn(vcJwt);

            doNothing().when(certificateValidationService).extractAndVerifyCertificate(any(), eq(vcHeader),eq("issuer"));

            // Step 8: Get the holder's public key
            PublicKey holderPublicKey = generateECPublicKey();
            when(didService.getPublicKeyFromDid(learCredentialEmployeeV1.mandateeId())).thenReturn(holderPublicKey);

            // Mock jwtService.verifyJWTSignature for the Verifiable Presentation
            doNothing().when(jwtService).verifyJWTWithECKey(verifiablePresentation, holderPublicKey);

            assertDoesNotThrow(() ->
                    vpServiceImpl.validateVerifiablePresentation(verifiablePresentation)
            );

            // Verify interactions
            verify(jwtService).verifyJWTWithECKey(verifiablePresentation, holderPublicKey);
        }
    }

    @Test
    void validateNewVerifiablePresentation_success() throws Exception {
        // Given
        String verifiablePresentation = "valid.vp.jwt";
        String vcJwt = "valid.vc.jwt";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mockedSignedJWT = mockStatic(SignedJWT.class)) {

            mockedSignedJWT.when(() -> SignedJWT.parse(verifiablePresentation)).thenReturn(vpSignedJWT);
            mockedSignedJWT.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            // VP header -> kid (holder DID)
            com.nimbusds.jose.JWSHeader vpHeader = mock(com.nimbusds.jose.JWSHeader.class);
            when(vpSignedJWT.getHeader()).thenReturn(vpHeader);
            when(vpHeader.getKeyID()).thenReturn("did:example:holder#key-1");

            // VP claims: iss/sub (optional) and vp claim with VC
            JWTClaimsSet vpClaimsSet = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaimsSet);
            when(vpClaimsSet.getIssuer()).thenReturn("did:example:holder");
            when(vpClaimsSet.getSubject()).thenReturn("did:example:holder");
            when(vpClaimsSet.getClaim("vp")).thenReturn(Map.of("verifiableCredential", List.of(vcJwt)));

            // VC claims: sub used for binding fallback/logging
            JWTClaimsSet vcClaimsSet = mock(JWTClaimsSet.class);
            when(vcSignedJWT.getJWTClaimsSet()).thenReturn(vcClaimsSet);
            when(vcClaimsSet.getSubject()).thenReturn("did:example:holder");

            // VC payload
            Payload payload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(vcSignedJWT)).thenReturn(payload);

            Map<String, Object> vcFromPayload = new HashMap<>();
            vcFromPayload.put("type", List.of("LEARCredentialEmployee"));
            vcFromPayload.put("@context", LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT);
            when(jwtService.getVCFromPayload(payload)).thenReturn(vcFromPayload);

            // Map -> credential domain object
            LEARCredentialEmployeeV1 cred = mock(LEARCredentialEmployeeV1.class);
            when(objectMapper.convertValue(vcFromPayload, LEARCredentialEmployeeV1.class)).thenReturn(cred);

            // Time window ok
            when(cred.validFrom()).thenReturn(ZonedDateTime.now().minusMinutes(1).toString());
            when(cred.validUntil()).thenReturn(ZonedDateTime.now().plusMinutes(5).toString());

            // Revocation path: old (no credentialStatus)
            when(cred.learCredentialStatusExist()).thenReturn(false);
            when(cred.id()).thenReturn("urn:uuid:1234");
            when(trustFrameworkService.getRevokedCredentialIds()).thenReturn(List.of());

            // Types
            when(cred.type()).thenReturn(List.of("LEARCredentialEmployee"));

            // Issuer
            var issuer = mock(es.in2.vcverifier.model.credentials.Issuer.class);
            when(cred.issuer()).thenReturn(issuer);
            when(issuer.getId()).thenReturn("did:elsi:VATES-FOO"); // IMPORTANT: must start with did:elsi:

            // Issuer capabilities include this credential type
            List<IssuerCredentialsCapabilities> issuerCapabilitiesList = List.of(
                    IssuerCredentialsCapabilities.builder()
                            .credentialsType("LEARCredentialEmployee")
                            .validFor(null)
                            .claims(null)
                            .build()
            );
            when(trustFrameworkService.getTrustedIssuerListData("did:elsi:VATES-FOO")).thenReturn(issuerCapabilitiesList);

            // Mandator check
            when(cred.mandatorOrganizationIdentifier()).thenReturn("VATES-FOO");
            when(trustFrameworkService.getTrustedIssuerListData(DID_ELSI_PREFIX + "VATES-FOO")).thenReturn(issuerCapabilitiesList);

            // Certificate validation (uses issuer DID substring after "did:elsi:")
            Map<String, Object> vcHeaderMap = new HashMap<>();
            vcHeaderMap.put("x5c", List.of("base64Cert"));

            com.nimbusds.jose.JWSHeader vcHeader = mock(com.nimbusds.jose.JWSHeader.class);
            when(vcSignedJWT.getHeader()).thenReturn(vcHeader);
            when(vcHeader.toJSONObject()).thenReturn(vcHeaderMap);

            when(vcSignedJWT.serialize()).thenReturn(vcJwt);

            doNothing().when(certificateValidationService)
                    .extractAndVerifyCertificate(eq(vcJwt), eq(vcHeaderMap), eq("VATES-FOO"));

            // PoP signature verification of VP
            PublicKey holderPublicKey = generateECPublicKey();
            when(didService.getPublicKeyFromDid("did:example:holder")).thenReturn(holderPublicKey);
            doNothing().when(jwtService).verifyJWTWithECKey(verifiablePresentation, holderPublicKey);

            // Binding: make VC bound DID == holder DID via credentialSubjectId
            when(cred.credentialSubjectId()).thenReturn("did:example:holder");

            assertDoesNotThrow(() -> vpServiceImpl.validateVerifiablePresentation(verifiablePresentation));

            verify(jwtService).verifyJWTWithECKey(verifiablePresentation, holderPublicKey);
            verify(certificateValidationService).extractAndVerifyCertificate(eq(vcJwt), eq(vcHeaderMap), eq("VATES-FOO"));
            verify(didService).getPublicKeyFromDid("did:example:holder");
        }
    }

    @Test
    void validateNewVerifiablePresentation_revoked() throws Exception {
        // Given
        String verifiablePresentation = "valid.vp.jwt";
        String vcJwt = "valid.vc.jwt";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mockedSignedJWT = mockStatic(SignedJWT.class)) {

            mockedSignedJWT.when(() -> SignedJWT.parse(verifiablePresentation)).thenReturn(vpSignedJWT);
            mockedSignedJWT.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            // VP -> contains VC JWT
            JWTClaimsSet vpClaimsSet = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaimsSet);
            when(vpClaimsSet.getClaim("vp")).thenReturn(Map.of("verifiableCredential", List.of(vcJwt)));

            // VC subject (not critical here)
            JWTClaimsSet vcClaimsSet = mock(JWTClaimsSet.class);
            when(vcSignedJWT.getJWTClaimsSet()).thenReturn(vcClaimsSet);
            when(vcClaimsSet.getSubject()).thenReturn("did:example:any");

            // VC payload
            Payload payload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(vcSignedJWT)).thenReturn(payload);

            Map<String, Object> vcFromPayload = new HashMap<>();
            vcFromPayload.put("id", "urn:uuid:1234");
            vcFromPayload.put("type", List.of("LEARCredentialEmployee"));
            vcFromPayload.put("@context", LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT);
            when(jwtService.getVCFromPayload(payload)).thenReturn(vcFromPayload);

            // Map -> credential domain object
            LEARCredentialEmployeeV1 cred = mock(LEARCredentialEmployeeV1.class);
            when(objectMapper.convertValue(vcFromPayload, LEARCredentialEmployeeV1.class)).thenReturn(cred);

            // Time window ok
            when(cred.validFrom()).thenReturn(ZonedDateTime.now().minusMinutes(1).toString());
            when(cred.validUntil()).thenReturn(ZonedDateTime.now().plusMinutes(5).toString());

            // Revocation path: old (no credentialStatus) -> revoked list contains the id
            when(cred.learCredentialStatusExist()).thenReturn(false);
            when(cred.id()).thenReturn("urn:uuid:1234");
            when(trustFrameworkService.getRevokedCredentialIds()).thenReturn(List.of("urn:uuid:1234"));

            assertThrows(CredentialRevokedException.class, () ->
                    vpServiceImpl.validateVerifiablePresentation(verifiablePresentation)
            );

            // Should fail early (before PoP / did resolution)
            verifyNoInteractions(didService);
            verify(jwtService, never()).verifyJWTWithECKey(anyString(), any());
        }
    }

    @Test
    void validateOldVerifiablePresentation_revocated() throws Exception {
        // Given
        String verifiablePresentation = "valid.vp.jwt";
        LEARCredentialEmployeeV1 learCredentialEmployeeV1 = getLEARCredentialEmployee();

        // Step 1: Parse the VP JWT
        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        try (MockedStatic<SignedJWT> mockedSignedJWT = mockStatic(SignedJWT.class)) {

            mockedSignedJWT.when(() -> SignedJWT.parse(verifiablePresentation)).thenReturn(vpSignedJWT);

            // Set up the VP claims
            JWTClaimsSet vpClaimsSet = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaimsSet);

            // Mock the "vp" claim in the VP
            Map<String, Object> vcClaimMap = new HashMap<>();
            String vcJwt = "valid.vc.jwt";
            vcClaimMap.put("verifiableCredential", List.of(vcJwt));
            when(vpClaimsSet.getClaim("vp")).thenReturn(vcClaimMap);

            // Step 2: Parse the VC JWT
            SignedJWT jwtCredential = mock(SignedJWT.class);
            mockedSignedJWT.when(() -> SignedJWT.parse(vcJwt)).thenReturn(jwtCredential);

            Payload payload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(jwtCredential)).thenReturn(payload);

            // Step 3: Validate the credential id is not in the revoked list
            // Create a vcFromPayload Map
            LinkedTreeMap<String, Object> vcFromPayload = new LinkedTreeMap<>();
            when(jwtService.getVCFromPayload(payload)).thenReturn(vcFromPayload);

            when(trustFrameworkService.getRevokedCredentialIds()).thenReturn(List.of("urn:uuid:1234"));

            // Step 4: Extract and validate credential types
            vcFromPayload.put("id", "urn:uuid:1234");
            vcFromPayload.put("type", List.of("LEARCredentialEmployee"));
            vcFromPayload.put("@context", LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT);

            when(objectMapper.convertValue(vcFromPayload, LEARCredentialEmployeeV1.class)).thenReturn(learCredentialEmployeeV1);

            assertThrows(CredentialRevokedException.class, () ->
                    vpServiceImpl.validateVerifiablePresentation(verifiablePresentation)
            );


        }
    }

    @Test
    void validateVerifiablePresentation_invalidTimeWindowForExpired() throws Exception {
        // Given
        String invalidVP = "invalid-time-window.vp.jwt";
        ZonedDateTime now = ZonedDateTime.now();
        LEARCredentialEmployeeV1 expiredCredential = LEARCredentialEmployeeV1.builder()
                .validUntil(now.minusDays(1).toString())
                .validFrom(now.minusDays(2).toString())
                .build();

        // Mock parsing del VP
        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        try (MockedStatic<SignedJWT> mockedSignedJWT = mockStatic(SignedJWT.class)) {
            mockedSignedJWT.when(() -> SignedJWT.parse(invalidVP)).thenReturn(vpSignedJWT);

            // Configurar claims del VP
            JWTClaimsSet vpClaimsSet = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaimsSet);

            Map<String, Object> vcClaimMap = new HashMap<>();
            String vcJwt = "invalid-time-window.vc.jwt";
            vcClaimMap.put("verifiableCredential", List.of(vcJwt));
            when(vpClaimsSet.getClaim("vp")).thenReturn(vcClaimMap);

            // Mock parsing del VC
            SignedJWT jwtCredential = mock(SignedJWT.class);
            mockedSignedJWT.when(() -> SignedJWT.parse(vcJwt)).thenReturn(jwtCredential);

            Payload payload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(jwtCredential)).thenReturn(payload);

            LinkedTreeMap<String, Object> vcFromPayload = new LinkedTreeMap<>();
            vcFromPayload.put("type", List.of("LEARCredentialEmployee"));
            vcFromPayload.put("@context", LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT);
            when(jwtService.getVCFromPayload(payload)).thenReturn(vcFromPayload);
            when(objectMapper.convertValue(vcFromPayload, LEARCredentialEmployeeV1.class)).thenReturn(expiredCredential);

            assertThrows(CredentialExpiredException.class, () ->
                    vpServiceImpl.validateVerifiablePresentation(invalidVP)
            );

        }
    }

    @Test
    void validateVerifiablePresentation_invalidTimeWindowForNotValidYet() throws Exception {
        // Given
        String invalidVP = "invalid-time-window.vp.jwt";
        ZonedDateTime now = ZonedDateTime.now();
        LEARCredentialEmployeeV1 expiredCredential = LEARCredentialEmployeeV1.builder()
                .validUntil(now.plusDays(1).toString())
                .validFrom(now.plusDays(1).toString())
                .build();

        // Mock parsing del VP
        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        try (MockedStatic<SignedJWT> mockedSignedJWT = mockStatic(SignedJWT.class)) {
            mockedSignedJWT.when(() -> SignedJWT.parse(invalidVP)).thenReturn(vpSignedJWT);

            // Configurar claims del VP
            JWTClaimsSet vpClaimsSet = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaimsSet);

            Map<String, Object> vcClaimMap = new HashMap<>();
            String vcJwt = "invalid-time-window.vc.jwt";
            vcClaimMap.put("verifiableCredential", List.of(vcJwt));
            when(vpClaimsSet.getClaim("vp")).thenReturn(vcClaimMap);

            // Mock parsing del VC
            SignedJWT jwtCredential = mock(SignedJWT.class);
            mockedSignedJWT.when(() -> SignedJWT.parse(vcJwt)).thenReturn(jwtCredential);

            Payload payload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(jwtCredential)).thenReturn(payload);

            LinkedTreeMap<String, Object> vcFromPayload = new LinkedTreeMap<>();
            vcFromPayload.put("type", List.of("LEARCredentialEmployee"));
            vcFromPayload.put("@context", LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT);
            when(jwtService.getVCFromPayload(payload)).thenReturn(vcFromPayload);
            when(objectMapper.convertValue(vcFromPayload, LEARCredentialEmployeeV1.class)).thenReturn(expiredCredential);

            assertThrows(CredentialNotActiveException.class, () ->
                    vpServiceImpl.validateVerifiablePresentation(invalidVP)
            );

        }
    }

    private ECPublicKey generateECPublicKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        return (ECPublicKey) keyPairGenerator.generateKeyPair().getPublic();
    }

    private LEARCredentialEmployeeV1 getLEARCredentialEmployee(){
        MandateeV1 mandateeV1 = MandateeV1.builder()
                .id("did:key:1234")
                .firstName("John")
                .lastName("Doe")
                .email("john.doe@example.com")
                .build();
        Mandator mandator = Mandator.builder()
                .organizationIdentifier("VATIT-1234")
                .build();
        MandateV1 mandate = MandateV1.builder()
                .mandatee(mandateeV1)
                .mandator(mandator)
                .build();
        CredentialSubjectV1 credentialSubject = CredentialSubjectV1.builder()
                .mandate(mandate)
                .build();
        return LEARCredentialEmployeeV1.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .context(LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT)
                .id("urn:uuid:1234")
                .issuer(SimpleIssuer.builder()
                        .id("did:elsi:issuer")
                        .build())
                .credentialSubjectV1(credentialSubject)
                .validUntil(ZonedDateTime.now().plusDays(1).toString())
                .validFrom(ZonedDateTime.now().toString())
                .credentialStatus(null)
                .build();
    }

    private LEARCredentialEmployeeV1 getNewLEARCredentialEmployee(){
        MandateeV1 mandateeV1 = MandateeV1.builder()
                .id("did:key:1234")
                .firstName("John")
                .lastName("Doe")
                .email("john.doe@example.com")
                .build();
        Mandator mandator = Mandator.builder()
                .organizationIdentifier("VATIT-1234")
                .build();
        MandateV1 mandate = MandateV1.builder()
                .mandatee(mandateeV1)
                .mandator(mandator)
                .build();
        CredentialSubjectV1 credentialSubject = CredentialSubjectV1.builder()
                .mandate(mandate)
                .build();
        CredentialStatus credentialStatus = CredentialStatus.builder()
                .id("urn:uuid:1234")
                .type("LEARCredentialEmployee")
                .purpose("revocation")
                .index("1")
                .credentials("url/status/1")
                .build();
        return LEARCredentialEmployeeV1.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .context(LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT)
                .id("urn:uuid:1234")
                .issuer(SimpleIssuer.builder()
                        .id("did:elsi:issuer")
                        .build())
                .credentialSubjectV1(credentialSubject)
                .validUntil(ZonedDateTime.now().plusDays(1).toString())
                .validFrom(ZonedDateTime.now().toString())
                .credentialStatus(credentialStatus)
                .build();
    }

    @Test
    void extractDidFromKidIssSub_validKidWithFragment_returnsDidWithoutFragment() throws Exception {
        VpServiceImpl service = new VpServiceImpl(null, null, null, null, null);
        Method method = VpServiceImpl.class.getDeclaredMethod("extractDidFromKidIssSub", String.class, String.class, String.class);
        method.setAccessible(true);

        String kid = "did:example:12345#fragment";
        String iss = null;
        String sub = null;

        String result = (String) method.invoke(service, kid, iss, sub);
        assertEquals("did:example:12345", result);
    }

    @Test
    void extractDidFromKidIssSub_validKidWithoutFragment_returnsKid() throws Exception {
        VpServiceImpl service = new VpServiceImpl(null, null, null, null, null);
        Method method = VpServiceImpl.class.getDeclaredMethod("extractDidFromKidIssSub", String.class, String.class, String.class);
        method.setAccessible(true);

        String kid = "did:example:12345";
        String iss = null;
        String sub = null;

        String result = (String) method.invoke(service, kid, iss, sub);
        assertEquals("did:example:12345", result);
    }

    @Test
    void extractDidFromKidIssSub_invalidKid_validIss_returnsIss() throws Exception {
        VpServiceImpl service = new VpServiceImpl(null, null, null, null, null);
        Method method = VpServiceImpl.class.getDeclaredMethod("extractDidFromKidIssSub", String.class, String.class, String.class);
        method.setAccessible(true);

        String kid = "invalid-kid";
        String iss = "did:example:iss";
        String sub = null;

        String result = (String) method.invoke(service, kid, iss, sub);
        assertEquals("did:example:iss", result);
    }

    @Test
    void extractDidFromKidIssSub_invalidKid_invalidIss_validSub_returnsSub() throws Exception {
        VpServiceImpl service = new VpServiceImpl(null, null, null, null, null);
        Method method = VpServiceImpl.class.getDeclaredMethod("extractDidFromKidIssSub", String.class, String.class, String.class);
        method.setAccessible(true);

        String kid = "invalid-kid";
        String iss = "invalid-iss";
        String sub = "did:example:sub";

        String result = (String) method.invoke(service, kid, iss, sub);
        assertEquals("did:example:sub", result);
    }

    @Test
    void extractDidFromKidIssSub_allInvalid_returnsNull() throws Exception {
        VpServiceImpl service = new VpServiceImpl(null, null, null, null, null);
        Method method = VpServiceImpl.class.getDeclaredMethod("extractDidFromKidIssSub", String.class, String.class, String.class);
        method.setAccessible(true);

        String kid = "invalid-kid";
        String iss = "invalid-iss";
        String sub = "invalid-sub";

        String result = (String) method.invoke(service, kid, iss, sub);
        assertNull(result);
    }

    @Test
    void safeGetCredentialSubjectId_throwsException_returnsNull() throws Exception {
        // Arrange
        VpServiceImpl service = new VpServiceImpl(null, null, null, null, null);
        Method method = VpServiceImpl.class.getDeclaredMethod("safeGetCredentialSubjectId", LEARCredential.class);
        method.setAccessible(true);

        LEARCredential mockCredential = mock(LEARCredential.class);
        doThrow(new RuntimeException("Error getting credential subject ID")).when(mockCredential).credentialSubjectId();

        // Act
        String result = (String) method.invoke(service, mockCredential);

        // Assert
        assertNull(result);
    }

    @Test
    void safeGetCredentialSubjectId_validId_returnsId() throws Exception {
        // Arrange
        VpServiceImpl service = new VpServiceImpl(null, null, null, null, null);
        Method method = VpServiceImpl.class.getDeclaredMethod("safeGetCredentialSubjectId", LEARCredential.class);
        method.setAccessible(true);

        LEARCredential mockCredential = mock(LEARCredential.class);
        when(mockCredential.credentialSubjectId()).thenReturn("did:example:123");

        // Act
        String result = (String) method.invoke(service, mockCredential);

        // Assert
        assertEquals("did:example:123", result);
    }
    @Test
    void extractBoundDidFromCredential_csIdValidAndMismatchWithVcSub_returnsCsIdWithWarning() throws Exception {
        // Arrange
        VpServiceImpl service = new VpServiceImpl(null, null, null, null, null);
        Method method = VpServiceImpl.class.getDeclaredMethod("extractBoundDidFromCredential", LEARCredential.class, String.class);
        method.setAccessible(true);

        // Mock LEARCredential to return a valid csId
        LEARCredential mockCredential = mock(LEARCredential.class);
        when(mockCredential.credentialSubjectId()).thenReturn("did:example:csid");

        // vcSub is different from csId
        String vcSub = "did:example:othersub";

        // Act
        String result = (String) method.invoke(service, mockCredential, vcSub);

        // Assert
        assertEquals("did:example:csid", result);

    }

    @Test
    void validateVerifiablePresentation_cryptographicBindingMismatch_throwsInvalidScopeException() throws Exception {
        // Arrange
        String vpToken = "valid.vp.jwt";
        String vcToken = "valid.vc.jwt";

        VpServiceImpl service = new VpServiceImpl(jwtService, objectMapper, trustFrameworkService, didService, certificateValidationService);

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mocked = mockStatic(SignedJWT.class)) {
            mocked.when(() -> SignedJWT.parse(vpToken)).thenReturn(vpSignedJWT);
            mocked.when(() -> SignedJWT.parse(vcToken)).thenReturn(vcSignedJWT);

            // --- VP header -> holder DID (kid)
            com.nimbusds.jose.JWSHeader vpHeader = mock(com.nimbusds.jose.JWSHeader.class);
            when(vpSignedJWT.getHeader()).thenReturn(vpHeader);
            when(vpHeader.getKeyID()).thenReturn("did:example:holder");

            // --- VP claims -> vp.verifiableCredential = [vcToken]
            JWTClaimsSet vpClaims = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaims);
            when(vpClaims.getClaim("vp")).thenReturn(Map.of("verifiableCredential", List.of(vcToken)));

            // --- VC claims -> sub (opcional, pero evita NPE en tu log de [BIND] VC JWT sub=...)
            JWTClaimsSet vcClaims = mock(JWTClaimsSet.class);
            when(vcSignedJWT.getJWTClaimsSet()).thenReturn(vcClaims);
            when(vcClaims.getSubject()).thenReturn("did:example:somebody-else");

            // --- Payload extraction
            Payload payload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(vcSignedJWT)).thenReturn(payload);

            // --- VC from payload must be a Map (NO un LEARCredential mock), o caerás en CredentialMappingException
            LinkedTreeMap<String, Object> vcFromPayload = new LinkedTreeMap<>();
            vcFromPayload.put("type", List.of("LEARCredentialEmployee"));
            vcFromPayload.put("@context", LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT);
            when(jwtService.getVCFromPayload(payload)).thenReturn(vcFromPayload);

            // --- Convert to credential object
            LEARCredentialEmployeeV1 cred = mock(LEARCredentialEmployeeV1.class);
            when(objectMapper.convertValue(vcFromPayload, LEARCredentialEmployeeV1.class)).thenReturn(cred);

            // Time window OK
            when(cred.validFrom()).thenReturn(ZonedDateTime.now().minusMinutes(1).toString());
            when(cred.validUntil()).thenReturn(ZonedDateTime.now().plusMinutes(5).toString());

            // Revocation path (old)
            when(cred.learCredentialStatusExist()).thenReturn(false);
            when(cred.id()).thenReturn("urn:uuid:test");
            when(trustFrameworkService.getRevokedCredentialIds()).thenReturn(List.of());

            // Issuer + capabilities OK
            var issuer = mock(es.in2.vcverifier.model.credentials.Issuer.class);
            when(cred.issuer()).thenReturn(issuer);
            when(issuer.getId()).thenReturn("did:elsi:VATES-FOO");
            when(cred.type()).thenReturn(List.of("LEARCredentialEmployee"));

            List<IssuerCredentialsCapabilities> caps = List.of(
                    IssuerCredentialsCapabilities.builder()
                            .credentialsType("LEARCredentialEmployee")
                            .validFor(null)
                            .claims(null)
                            .build()
            );
            when(trustFrameworkService.getTrustedIssuerListData("did:elsi:VATES-FOO")).thenReturn(caps);

            // Mandator validation OK
            when(cred.mandatorOrganizationIdentifier()).thenReturn("VATES-FOO");
            when(trustFrameworkService.getTrustedIssuerListData(DID_ELSI_PREFIX + "VATES-FOO")).thenReturn(caps);

            // Certificate validation no-op
            JWSHeader vcHeader = mock(JWSHeader.class);
            when(vcSignedJWT.getHeader()).thenReturn(vcHeader);
            when(vcHeader.toJSONObject()).thenReturn(Map.of("x5c", List.of("base64Cert")));
            when(vcSignedJWT.serialize()).thenReturn(vcToken);
            doNothing().when(certificateValidationService).extractAndVerifyCertificate(any(), anyMap(), anyString());
            when(cred.credentialSubjectId()).thenReturn("did:example:bound-did");

            // PoP signature OK
            PublicKey publicKey = mock(PublicKey.class);
            when(didService.getPublicKeyFromDid("did:example:holder")).thenReturn(publicKey);
            doNothing().when(jwtService).verifyJWTWithECKey(vpToken, publicKey);

            // Act & Assert
            assertThrows(InvalidScopeException.class, () -> service.validateVerifiablePresentation(vpToken));
        }
    }


    @Test
    void validateVerifiablePresentation_signatureVerificationFails_throwsRuntimeException() throws Exception {
        String vpToken = "valid.vp.jwt";
        String vcJwt = "valid.vc.jwt";
        String holderDid = "did:example:holder";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mocked = mockStatic(SignedJWT.class)) {
            mocked.when(() -> SignedJWT.parse(vpToken)).thenReturn(vpSignedJWT);

            var vpHeader = mock(com.nimbusds.jose.JWSHeader.class);
            when(vpSignedJWT.getHeader()).thenReturn(vpHeader);
            when(vpHeader.getKeyID()).thenReturn(holderDid);

            JWTClaimsSet vpClaims = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaims);
            when(vpClaims.getClaim("vp")).thenReturn(Map.of("verifiableCredential", List.of(vcJwt)));

            mocked.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            JWTClaimsSet vcClaims = mock(JWTClaimsSet.class);
            when(vcSignedJWT.getJWTClaimsSet()).thenReturn(vcClaims);
            when(vcClaims.getSubject()).thenReturn(holderDid);

            Payload payload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(vcSignedJWT)).thenReturn(payload);

            var vcFromPayload = new LinkedTreeMap<String, Object>();
            vcFromPayload.put("type", List.of("LEARCredentialEmployee"));
            vcFromPayload.put("@context", LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT);
            when(jwtService.getVCFromPayload(payload)).thenReturn(vcFromPayload);

            var cred = mock(es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV1.class);
            when(objectMapper.convertValue(vcFromPayload, es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV1.class))
                    .thenReturn(cred);

            when(cred.validFrom()).thenReturn(ZonedDateTime.now().minusMinutes(1).toString());
            when(cred.validUntil()).thenReturn(ZonedDateTime.now().plusMinutes(5).toString());
            when(cred.learCredentialStatusExist()).thenReturn(false);
            when(cred.id()).thenReturn("urn:uuid:test");
            when(trustFrameworkService.getRevokedCredentialIds()).thenReturn(List.of());

            var issuer = mock(es.in2.vcverifier.model.credentials.Issuer.class);
            when(cred.issuer()).thenReturn(issuer);
            when(issuer.getId()).thenReturn("did:elsi:VATES-FOO");
            when(cred.type()).thenReturn(List.of("LEARCredentialEmployee"));

            List<IssuerCredentialsCapabilities> caps = List.of(
                    IssuerCredentialsCapabilities.builder().credentialsType("LEARCredentialEmployee").validFor(null).claims(null).build()
            );
            when(trustFrameworkService.getTrustedIssuerListData("did:elsi:VATES-FOO")).thenReturn(caps);

            JWSHeader vcHeader = mock(JWSHeader.class);
            when(vcSignedJWT.getHeader()).thenReturn(vcHeader);
            when(vcHeader.toJSONObject()).thenReturn(Map.of("x5c", List.of("base64Cert")));
            when(vcSignedJWT.serialize()).thenReturn(vcJwt);
            doNothing().when(certificateValidationService).extractAndVerifyCertificate(any(), anyMap(), anyString());

            when(cred.mandatorOrganizationIdentifier()).thenReturn("VATES-FOO");
            when(trustFrameworkService.getTrustedIssuerListData(DID_ELSI_PREFIX + "VATES-FOO")).thenReturn(caps);

            PublicKey publicKey = mock(PublicKey.class);
            when(didService.getPublicKeyFromDid(holderDid)).thenReturn(publicKey);

            doThrow(new RuntimeException("Signature verification failed"))
                    .when(jwtService).verifyJWTWithECKey(vpToken, publicKey);

            RuntimeException ex = assertThrows(RuntimeException.class,
                    () -> vpServiceImpl.validateVerifiablePresentation(vpToken));

            assertEquals("Signature verification failed", ex.getMessage());
        }
    }

    @Test
    void validateVerifiablePresentation_holderDidCannotBeResolved_throwsInvalidScopeException() throws Exception {
        String vpToken = "valid.vp.jwt";
        String vcJwt = "valid.vc.jwt";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mocked = mockStatic(SignedJWT.class)) {
            mocked.when(() -> SignedJWT.parse(vpToken)).thenReturn(vpSignedJWT);
            mocked.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            // VP header kid NO did:
            var vpHeader = mock(com.nimbusds.jose.JWSHeader.class);
            when(vpSignedJWT.getHeader()).thenReturn(vpHeader);
            when(vpHeader.getKeyID()).thenReturn("not-a-did");

            JWTClaimsSet vpClaims = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaims);
            when(vpClaims.getIssuer()).thenReturn("https://issuer.example");
            when(vpClaims.getSubject()).thenReturn("1234567890");
            when(vpClaims.getClaim("vp")).thenReturn(Map.of("verifiableCredential", List.of(vcJwt)));

            JWTClaimsSet vcClaims = mock(JWTClaimsSet.class);
            when(vcSignedJWT.getJWTClaimsSet()).thenReturn(vcClaims);
            when(vcClaims.getSubject()).thenReturn("1234567890"); // no did

            Payload payload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(vcSignedJWT)).thenReturn(payload);

            var vcFromPayload = new LinkedTreeMap<String, Object>();
            vcFromPayload.put("type", List.of("LEARCredentialEmployee"));
            vcFromPayload.put("@context", LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT);
            when(jwtService.getVCFromPayload(payload)).thenReturn(vcFromPayload);

            LEARCredentialEmployeeV1 cred = mock(LEARCredentialEmployeeV1.class);
            when(objectMapper.convertValue(vcFromPayload, LEARCredentialEmployeeV1.class)).thenReturn(cred);

            when(cred.validFrom()).thenReturn(ZonedDateTime.now().minusMinutes(1).toString());
            when(cred.validUntil()).thenReturn(ZonedDateTime.now().plusMinutes(5).toString());
            when(cred.learCredentialStatusExist()).thenReturn(false);
            when(cred.id()).thenReturn("urn:uuid:test");
            when(trustFrameworkService.getRevokedCredentialIds()).thenReturn(List.of());

            var issuer = mock(es.in2.vcverifier.model.credentials.Issuer.class);
            when(cred.issuer()).thenReturn(issuer);
            when(issuer.getId()).thenReturn("did:elsi:VATES-FOO");
            when(cred.type()).thenReturn(List.of("LEARCredentialEmployee"));

            List<IssuerCredentialsCapabilities> caps = List.of(
                    IssuerCredentialsCapabilities.builder().credentialsType("LEARCredentialEmployee").validFor(null).claims(null).build()
            );
            when(trustFrameworkService.getTrustedIssuerListData("did:elsi:VATES-FOO")).thenReturn(caps);

            // cert + mandator OK
            JWSHeader header = mock(JWSHeader.class);
            when(vcSignedJWT.getHeader()).thenReturn(header);
            when(header.toJSONObject()).thenReturn(Map.of("x5c", List.of("base64Cert")));
            when(vcSignedJWT.serialize()).thenReturn(vcJwt);
            doNothing().when(certificateValidationService).extractAndVerifyCertificate(any(), anyMap(), anyString());

            when(cred.mandatorOrganizationIdentifier()).thenReturn("VATES-FOO");
            when(trustFrameworkService.getTrustedIssuerListData(DID_ELSI_PREFIX + "VATES-FOO")).thenReturn(caps);

            assertThrows(InvalidScopeException.class,
                    () -> vpServiceImpl.validateVerifiablePresentation(vpToken));
        }
    }




    @Test
    void validateVerifiablePresentation_publicKeyRetrievalFails_throwsRuntimeException() throws Exception {
        String vpToken = "valid.vp.jwt";
        String vcJwt = "valid.vc.jwt";
        String holderDid = "did:example:holder";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mocked = mockStatic(SignedJWT.class)) {
            mocked.when(() -> SignedJWT.parse(vpToken)).thenReturn(vpSignedJWT);

            // VP header kid => holder DID
            var vpHeader = mock(com.nimbusds.jose.JWSHeader.class);
            when(vpSignedJWT.getHeader()).thenReturn(vpHeader);
            when(vpHeader.getKeyID()).thenReturn(holderDid);

            // VP claims -> vp.verifiableCredential
            JWTClaimsSet vpClaims = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaims);
            when(vpClaims.getClaim("vp")).thenReturn(Map.of("verifiableCredential", List.of(vcJwt)));

            // VC parse
            mocked.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            JWTClaimsSet vcClaims = mock(JWTClaimsSet.class);
            when(vcSignedJWT.getJWTClaimsSet()).thenReturn(vcClaims);
            when(vcClaims.getSubject()).thenReturn(holderDid);

            Payload payload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(vcSignedJWT)).thenReturn(payload);

            var vcFromPayload = new LinkedTreeMap<String, Object>();
            vcFromPayload.put("type", List.of("LEARCredentialEmployee"));
            vcFromPayload.put("@context", LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT);
            when(jwtService.getVCFromPayload(payload)).thenReturn(vcFromPayload);

            var cred = mock(es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV1.class);
            when(objectMapper.convertValue(vcFromPayload, es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV1.class))
                    .thenReturn(cred);

            when(cred.validFrom()).thenReturn(ZonedDateTime.now().minusMinutes(1).toString());
            when(cred.validUntil()).thenReturn(ZonedDateTime.now().plusMinutes(5).toString());
            when(cred.learCredentialStatusExist()).thenReturn(false);
            when(cred.id()).thenReturn("urn:uuid:test");
            when(trustFrameworkService.getRevokedCredentialIds()).thenReturn(List.of());

            var issuer = mock(es.in2.vcverifier.model.credentials.Issuer.class);
            when(cred.issuer()).thenReturn(issuer);
            when(issuer.getId()).thenReturn("did:elsi:VATES-FOO");
            when(cred.type()).thenReturn(List.of("LEARCredentialEmployee"));

            List<IssuerCredentialsCapabilities> caps = List.of(
                    IssuerCredentialsCapabilities.builder().credentialsType("LEARCredentialEmployee").validFor(null).claims(null).build()
            );
            when(trustFrameworkService.getTrustedIssuerListData("did:elsi:VATES-FOO")).thenReturn(caps);

            JWSHeader vcHeader = mock(JWSHeader.class);
            when(vcSignedJWT.getHeader()).thenReturn(vcHeader);
            when(vcHeader.toJSONObject()).thenReturn(Map.of("x5c", List.of("base64Cert")));
            when(vcSignedJWT.serialize()).thenReturn(vcJwt);
            doNothing().when(certificateValidationService).extractAndVerifyCertificate(any(), anyMap(), anyString());

            when(cred.mandatorOrganizationIdentifier()).thenReturn("VATES-FOO");
            when(trustFrameworkService.getTrustedIssuerListData(DID_ELSI_PREFIX + "VATES-FOO")).thenReturn(caps);

            when(didService.getPublicKeyFromDid(holderDid))
                    .thenThrow(new RuntimeException("Public key not found"));

            RuntimeException ex = assertThrows(RuntimeException.class,
                    () -> vpServiceImpl.validateVerifiablePresentation(vpToken));

            assertEquals("Public key not found", ex.getMessage());
        }
    }

    @Test
    void validateVerifiablePresentation_holderDidIsNotDidFormat_throwsInvalidScopeException() throws Exception {
        String vpToken = "valid.vp.jwt";
        String vcJwt   = "valid.vc.jwt";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mocked = mockStatic(SignedJWT.class)) {
            mocked.when(() -> SignedJWT.parse(vpToken)).thenReturn(vpSignedJWT);
            mocked.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            com.nimbusds.jose.JWSHeader vpHeader = mock(com.nimbusds.jose.JWSHeader.class);
            when(vpSignedJWT.getHeader()).thenReturn(vpHeader);
            when(vpHeader.getKeyID()).thenReturn("invalid-kid"); // no did:

            JWTClaimsSet vpClaims = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaims);
            when(vpClaims.getIssuer()).thenReturn("https://issuer.example"); // no did:
            when(vpClaims.getSubject()).thenReturn("not-a-did-subject");     // no did:
            when(vpClaims.getClaim("vp")).thenReturn(Map.of("verifiableCredential", List.of(vcJwt)));

            JWTClaimsSet vcClaims = mock(JWTClaimsSet.class);
            when(vcSignedJWT.getJWTClaimsSet()).thenReturn(vcClaims);
            when(vcClaims.getSubject()).thenReturn("did:example:any");

            Payload payload = mock(Payload.class);
            when(jwtService.getPayloadFromSignedJWT(vcSignedJWT)).thenReturn(payload);

            LinkedTreeMap<String, Object> vcFromPayload = new LinkedTreeMap<>();
            vcFromPayload.put("type", List.of("LEARCredentialEmployee"));
            vcFromPayload.put("@context", LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT);
            when(jwtService.getVCFromPayload(payload)).thenReturn(vcFromPayload);

            LEARCredentialEmployeeV1 cred = mock(LEARCredentialEmployeeV1.class);
            when(objectMapper.convertValue(vcFromPayload, LEARCredentialEmployeeV1.class)).thenReturn(cred);

            when(cred.validFrom()).thenReturn(ZonedDateTime.now().minusMinutes(1).toString());
            when(cred.validUntil()).thenReturn(ZonedDateTime.now().plusMinutes(5).toString());

            when(cred.learCredentialStatusExist()).thenReturn(false);
            when(trustFrameworkService.getRevokedCredentialIds()).thenReturn(List.of());
            when(cred.id()).thenReturn("urn:uuid:test");
            when(cred.type()).thenReturn(List.of("LEARCredentialEmployee"));

            var issuer = mock(es.in2.vcverifier.model.credentials.Issuer.class);
            when(cred.issuer()).thenReturn(issuer);
            when(issuer.getId()).thenReturn("did:elsi:VATES-FOO");

            List<IssuerCredentialsCapabilities> caps = List.of(
                    IssuerCredentialsCapabilities.builder()
                            .credentialsType("LEARCredentialEmployee")
                            .validFor(null)
                            .claims(null)
                            .build()
            );
            when(trustFrameworkService.getTrustedIssuerListData("did:elsi:VATES-FOO")).thenReturn(caps);

            when(cred.mandatorOrganizationIdentifier()).thenReturn("VATES-FOO");
            when(trustFrameworkService.getTrustedIssuerListData(DID_ELSI_PREFIX + "VATES-FOO")).thenReturn(caps);

            com.nimbusds.jose.JWSHeader vcHeader = mock(com.nimbusds.jose.JWSHeader.class);
            when(vcSignedJWT.getHeader()).thenReturn(vcHeader);
            when(vcHeader.toJSONObject()).thenReturn(Map.of("x5c", List.of("base64Cert")));
            when(vcSignedJWT.serialize()).thenReturn(vcJwt);
            doNothing().when(certificateValidationService).extractAndVerifyCertificate(any(), anyMap(), anyString());

            assertThrows(InvalidScopeException.class, () -> vpServiceImpl.validateVerifiablePresentation(vpToken));

            verifyNoInteractions(didService);
            verify(jwtService, never()).verifyJWTWithECKey(anyString(), any());
        }
    }



}