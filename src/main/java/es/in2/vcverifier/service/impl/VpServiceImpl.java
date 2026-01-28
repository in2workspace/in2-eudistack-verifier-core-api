package es.in2.vcverifier.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.exception.*;
import es.in2.vcverifier.model.credentials.lear.LEARCredential;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV1;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV2;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV3;
import es.in2.vcverifier.model.credentials.lear.machine.LEARCredentialMachineV1;
import es.in2.vcverifier.model.credentials.lear.machine.LEARCredentialMachineV2;
import es.in2.vcverifier.model.enums.LEARCredentialType;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.service.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.text.ParseException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static es.in2.vcverifier.util.Constants.*;

/**
 * This class contains basic validation steps for the scope of validating a Verifiable Presentation (VP)
 * that includes a LEARCredential, following the technical guidelines described in the DOME document.
 * The current implementation includes:
 * - Validation of the Verifiable Credential (VC) issuer.
 * - Verification of the signature using the public key from the JWT.
 * - Extraction and validation of the mandatee ID from the credential subject.
 * - Verification that the VP is signed by the correct DID.
 * In future versions, additional verifications will be added to enhance the validation process.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class VpServiceImpl implements VpService {

    private final JWTService jwtService;
    private final ObjectMapper objectMapper;
    private final TrustFrameworkService trustFrameworkService;
    private final DIDService didService;
    private final CertificateValidationService certificateValidationService;


    @Override
    public void validateVerifiablePresentation(String verifiablePresentation) {
        log.info("Starting validation of Verifiable Presentation");
        // Step 1: Extract the Verifiable Credential (VC) from the VP (JWT)
        log.debug("VpServiceImpl -- validateVerifiablePresentation -- Extracting first Verifiable Credential from Verifiable Presentation");
        SignedJWT jwtCredential = extractFirstVerifiableCredential(verifiablePresentation);
        String vcSub = null;
        try {
            vcSub = jwtCredential.getJWTClaimsSet().getSubject();
            vcSub = normalizeDid(vcSub);
        } catch (Exception e) {
            log.warn("[BIND] Cannot read VC 'sub' from VC JWT claims", e);
        }
        log.info("[BIND] VC JWT sub={}", vcSub);
        Payload payload = jwtService.getPayloadFromSignedJWT(jwtCredential);
        log.debug("VpServiceImpl -- validateVerifiablePresentation -- Successfully extracted the Verifiable Credential payload");

        // Step 1.1: Map the payload to a VerifiableCredential object
        LEARCredential learCredential = mapPayloadToVerifiableCredential(payload);

        // Step 2: Validate the time window of the credential
        log.debug("VpServiceImpl -- validateVerifiablePresentation -- Validating the time window of the credential");
        validateCredentialTimeWindow(learCredential);

        // Step 3: Validate the old credential id is not in the revoked list
        if (hasCredentialStatus(learCredential)) {
            log.debug("CredentialStatus detected: {}", learCredential.credentialStatusId());
            if (!validateNewCredentialNotRevoked(learCredential)) {
                throw new CredentialRevokedException("Credential ID " + learCredential.id() + " is revoked.");
            }
        } else {
            log.debug("No CredentialStatus block found; using old ID check for credential {}", learCredential.id());
            if (!validateOldCredentialNotRevoked(learCredential.id())) {
                throw new CredentialRevokedException("Credential ID " + learCredential.id() + " is revoked.");
            }
        }
        log.info("Credential is not revoked");

        // Step 4: Validate the issuer
        String credentialIssuerDid = learCredential.issuer().getId();
        log.debug("VpServiceImpl -- validateVerifiablePresentation -- Retrieved issuer DID from payload: {}", credentialIssuerDid);

        // Step 5: Extract and validate credential types
        List<String> credentialTypes = learCredential.type();
        log.debug("VpServiceImpl -- validateVerifiablePresentation -- Credential types extracted: {}", credentialTypes);

        // Step 6: Retrieve the list of issuer capabilities
        log.debug("VpServiceImpl -- validateVerifiablePresentation -- Retrieving issuer capabilities for DID {}", credentialIssuerDid);
        List<IssuerCredentialsCapabilities> issuerCapabilitiesList = trustFrameworkService.getTrustedIssuerListData(credentialIssuerDid);
        log.info("Retrieved issuer capabilities");

        // Step 7: Validate credential type against issuer capabilities
        log.debug("VpServiceImpl -- validateVerifiablePresentation -- Validating credential types against issuer capabilities");
        validateCredentialTypeWithIssuerCapabilities(issuerCapabilitiesList, credentialTypes);
        log.info("Issuer DID {} is a trusted participant", credentialIssuerDid);

        // TODO remove step 7 after the advanced certificate validation component is implemented
        // Step 8: Verify the signature and the organizationId of the credential signature
        Map<String, Object> vcHeader = jwtCredential.getHeader().toJSONObject();
        certificateValidationService.extractAndVerifyCertificate(jwtCredential.serialize(),vcHeader, credentialIssuerDid.substring("did:elsi:".length())); // Extract public key from x5c certificate and validate OrganizationIdentifier

        // Step 9: Extract the mandator organization identifier from the Verifiable Credential
        String mandatorOrganizationIdentifier = learCredential.mandatorOrganizationIdentifier();
        log.debug("VpServiceImpl -- validateVerifiablePresentation -- Extracted Mandator Organization Identifier from Verifiable Credential: {}", mandatorOrganizationIdentifier);

        //TODO this must be validated against the participants list, not the issuer list
        // Validate the mandator with trusted issuer service, if is not present the trustedIssuerListService throws an exception
        trustFrameworkService.getTrustedIssuerListData(DID_ELSI_PREFIX + mandatorOrganizationIdentifier);
        log.info("Mandator OrganizationIdentifier {} is valid and allowed", mandatorOrganizationIdentifier);

        // Step 10: Validate the VP's signature (PoP) and cryptographic binding

        SignedJWT vpJwt;
        try {
            vpJwt = SignedJWT.parse(verifiablePresentation);
        } catch (Exception e) {
            throw new InvalidVPtokenException("Invalid vp_token JWT");
        }

        String vpKid = vpJwt.getHeader().getKeyID();
        String vpIss;
        String vpSub;
        try {
            var claims = vpJwt.getJWTClaimsSet();
            vpIss = claims.getIssuer();
            vpSub = claims.getSubject();
        } catch (Exception e) {
            throw new InvalidVPtokenException("Cannot read vp_token claims");
        }

        String holderDid = extractDidFromKidIssSub(vpKid, vpIss, vpSub);
        holderDid = normalizeDid(holderDid);

        if (holderDid == null || holderDid.isBlank()) {
            throw new InvalidScopeException("Cannot extract holder DID from VP (kid/iss/sub)");
        }

        log.info("[BIND] VP holder DID resolved as {}", holderDid);

        // PoP: verify VP signature with holder DID
        PublicKey holderPublicKey = didService.getPublicKeyFromDid(holderDid);
        jwtService.verifyJWTWithECKey(verifiablePresentation, holderPublicKey);
        log.info("VP's signature is valid, holder DID {} confirmed", holderDid);

        // Binding: VC bound DID (new first, then legacy)
        String boundDidFromVc = extractBoundDidFromCredential(learCredential, vcSub);

        if (boundDidFromVc == null || boundDidFromVc.isBlank()) {
            throw new InvalidScopeException("Credential missing cryptographic binding DID (credentialSubject.id or vc.jwt.sub or mandatee.id)");
        }

        log.info("[BIND] VC bound DID resolved as {}", boundDidFromVc);

        // 10.4 Enforce binding: holder DID must match VC bound DID
        if (!holderDid.equals(boundDidFromVc)) {
            throw new InvalidScopeException(
                    "Cryptographic binding mismatch: VP holder DID (" + holderDid + ") != VC bound DID (" + boundDidFromVc + ")"
            );
        }

        log.info("Cryptographic binding validated: VP holder DID matches VC bound DID");
        log.info("Verifiable Presentation validation completed successfully");

    }

    @Override
    public Object getCredentialFromTheVerifiablePresentation(String verifiablePresentation) {
        log.debug("VpServiceImpl -- getCredentialFromTheVerifiablePresentation -- Extracting Verifiable Credential object from Verifiable Presentation");
        // Step 1: Extract the Verifiable Credential (VC) from the VP (JWT)
        SignedJWT jwtCredential = extractFirstVerifiableCredential(verifiablePresentation);
        Payload payload = jwtService.getPayloadFromSignedJWT(jwtCredential);
        return jwtService.getVCFromPayload(payload);
    }

    @Override
    public JsonNode getCredentialFromTheVerifiablePresentationAsJsonNode(String verifiablePresentation) {
        log.debug("VpServiceImpl -- getCredentialFromTheVerifiablePresentationAsJsonNode -- Converting Verifiable Credential to JSON Node format");
        return convertObjectToJSONNode(getCredentialFromTheVerifiablePresentation(verifiablePresentation));
    }

    @Override
    public List<String> extractContextFromJson(JsonNode verifiableCredential) {
        JsonNode contextNode = verifiableCredential.get("@context");
        if (contextNode == null || !contextNode.isArray()) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    "'@context' field is missing or is not an array",
                    null));
        }

        List<String> contextList = new ArrayList<>();
        for (JsonNode node : contextNode) {
            if (!node.isTextual()) {
                throw new OAuth2AuthenticationException(new OAuth2Error(
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        "Elements of '@context' must be strings",
                        null));
            }
            contextList.add(node.asText());
        }
        return contextList;
    }

    private LEARCredential mapPayloadToVerifiableCredential(Payload payload) {
        Object vcObject = jwtService.getVCFromPayload(payload);
        try {
            Map<String, Object> vcMap = validateAndCastToMap(vcObject);
            List<String> types = extractAndValidateTypes(vcMap);
            return mapToSpecificCredential(vcMap, types);
        } catch (IllegalArgumentException e) {
            throw new CredentialMappingException("Error mapping VC payload to specific Verifiable Credential class: " + e.getMessage());
        }
    }

    private Map<String, Object> validateAndCastToMap(Object vcObject) {
        if (!(vcObject instanceof Map<?, ?> map)) {
            throw new CredentialMappingException("Invalid payload format for Verifiable Credential.");
        }

        // Ensure the map's keys are all types are Strings and values are Objects
        Map<String, Object> validatedMap = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String)) {
                throw new CredentialMappingException("Invalid key type found in Verifiable Credential map: " + entry.getKey());
            }
            validatedMap.put((String) entry.getKey(), entry.getValue());
        }

        return validatedMap;
    }


    private List<String> extractAndValidateTypes(Map<String, Object> vcMap) {
        Object typeObject = vcMap.get("type");

        // Validate that the "type" object is a list
        if (!(typeObject instanceof List<?> typeList)) {
            throw new CredentialMappingException("'type' key is not a list.");
        }

        // Ensure that all elements in the list are Strings
        if (!typeList.stream().allMatch(String.class::isInstance)) {
            throw new CredentialMappingException("'type' list contains non-string elements.");
        }

        // Safely cast the List<?> to List<String>
        return typeList.stream()
                .map(String.class::cast)
                .toList();
    }

    private List<String> extractContext(Map<String, Object> vcMap) {
        Object contextObj = vcMap.get("@context");
        if (!(contextObj instanceof List<?> contextList)) {
            throw new CredentialMappingException("The field '@context' is not a list.");
        }
        if (!contextList.stream().allMatch(String.class::isInstance)) {
            throw new CredentialMappingException("The field '@context' contains non-string elements.");
        }
        return contextList.stream().map(String.class::cast).toList();
    }


    private LEARCredential mapToSpecificCredential(Map<String, Object> vcMap, List<String> types) {
        List<String> contextList = extractContext(vcMap);

        if (types.contains(LEARCredentialType.LEAR_CREDENTIAL_EMPLOYEE.getValue())) {
            // Extract the '@context' field from the VC

            // Compare the context with the v1 and v2 constants
            if (contextList.equals(LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT)) {
                return objectMapper.convertValue(vcMap, LEARCredentialEmployeeV1.class);
            } else if (contextList.equals(LEAR_CREDENTIAL_EMPLOYEE_V2_CONTEXT)) {
                return objectMapper.convertValue(vcMap, LEARCredentialEmployeeV2.class);
            } else if(contextList.equals(LEAR_CREDENTIAL_EMPLOYEE_V3_CONTEXT)){
                return objectMapper.convertValue(vcMap, LEARCredentialEmployeeV3.class);
            } else {
                throw new InvalidCredentialTypeException("Unknown LEARCredentialEmployee version: " + contextList);
            }
        } else if (types.contains(LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue())) {
            if(contextList.equals(LEAR_CREDENTIAL_MACHINE_V2_CONTEXT)){
                return objectMapper.convertValue(vcMap, LEARCredentialMachineV2.class);
            } else {
                return objectMapper.convertValue(vcMap, LEARCredentialMachineV1.class);
            }
        }
        else {
            throw new InvalidCredentialTypeException("Unsupported credential type: " + types);
        }
    }


    private void validateCredentialTypeWithIssuerCapabilities(List<IssuerCredentialsCapabilities> issuerCapabilitiesList, List<String> credentialTypes) {
        // Iterate over each credential type in the verifiable credential
        for (String credentialType : credentialTypes) {
            // Check if any of the issuer capabilities support this credential type
            boolean isSupported = issuerCapabilitiesList.stream().anyMatch(capability -> capability.credentialsType().equals(credentialType));

            // If we find a matching capability, return from the method
            if (isSupported) {
                return;
            }
        }
        // If none of the credential types are supported, throw an exception
        throw new InvalidCredentialTypeException("Credential types " + credentialTypes + " are not supported by the issuer.");
    }

    private boolean hasCredentialStatus(LEARCredential credential) {
        if (!credential.learCredentialStatusExist()) {
            return false;
        }
        return credential.credentialStatusId() != null && !credential.credentialStatusId().isBlank() &&
                credential.credentialStatusType() != null && !credential.credentialStatusType().isBlank() &&
                credential.credentialStatusPurpose() != null && !credential.credentialStatusPurpose().isBlank();

    }

    private boolean validateOldCredentialNotRevoked(String credentialId) {
        List<String> revokedIds = trustFrameworkService.getRevokedCredentialIds();
        return !revokedIds.contains(credentialId); //negate because we want a true just only when really not exist

    }

    private boolean validateNewCredentialNotRevoked(LEARCredential learCredential) {
        log.info("validateNewCredentialNotRevoked, vc: {}", learCredential);
        if (!REVOCATION.equals(learCredential.credentialStatusPurpose())) {
            log.error("credentialStatus is not revocation: {}", learCredential.credentialStatusPurpose());
            return false;
        }

        String type = learCredential.credentialStatusType();

        if ("PlainListEntity".equals(type)) {
            log.info("Validating credential with PlainListEntity credential status");
            // Legacy JSON: list of nonces
            return !trustFrameworkService.getCredentialStatusListData(learCredential.statusListCredential())
                    .contains(learCredential.credentialStatusListIndex());
        }

        if ("BitstringStatusListEntry".equals(type)) {
            log.info("Validating credential with BitstringStatusListEntry credential status");
            // Modern VC-JWT: bitstring encoded list
            return !trustFrameworkService.isCredentialRevokedInBitstringStatusList(
                    learCredential.statusListCredential(),
                    learCredential.credentialStatusListIndex(),
                    learCredential.credentialStatusPurpose()
            );
        }

        throw new CredentialException("Unsupported credentialStatus.type: " + type);
    }


    private void validateCredentialTimeWindow(LEARCredential credential) {
        try {
            ZonedDateTime validFrom = ZonedDateTime.parse(credential.validFrom());
            ZonedDateTime validUntil = ZonedDateTime.parse(credential.validUntil());
            ZonedDateTime now = ZonedDateTime.now();

            // Check if the credential is not yet valid
            if (now.isBefore(validFrom)) {
                throw new CredentialNotActiveException("Credential is not yet valid. Valid from: " + validFrom);
            }

            // Check if the credential has expired
            if (now.isAfter(validUntil)) {
                throw new CredentialExpiredException("Credential has expired. Valid until: " + validUntil);
            }

        } catch (DateTimeParseException e) {
            throw new CredentialMappingException("Invalid date format in credential: " + e.getMessage());
        }
    }



    private JsonNode convertObjectToJSONNode(Object vcObject) throws JsonConversionException {
        JsonNode jsonNode;

        try {
            if (vcObject instanceof Map) {
                // Si el objeto es un Map, lo convertimos directamente a JsonNode
                jsonNode = objectMapper.convertValue(vcObject, JsonNode.class);
            } else if (vcObject instanceof JSONObject) {
                // Si el objeto es un JSONObject, lo convertimos a String y luego a JsonNode
                jsonNode = objectMapper.readTree(vcObject.toString());
            } else {
                throw new JsonConversionException("El tipo del objeto no es compatible para la conversión a JsonNode.");
            }
        } catch (Exception e) {
            throw new JsonConversionException("Error durante la conversión a JsonNode.");
        }
        return jsonNode;
    }

    private SignedJWT extractFirstVerifiableCredential(String verifiablePresentation) {
        try {
            // Parse the Verifiable Presentation (VP) JWT
            SignedJWT vpSignedJWT = SignedJWT.parse(verifiablePresentation);

            // Extract the "vp" claim
            Object vpClaim = vpSignedJWT.getJWTClaimsSet().getClaim("vp");

            Object vcClaim = getVcClaim(vpClaim);

            // Extract the first credential if it's a list or if it's a string
            Object firstCredential = getFirstCredential(vcClaim);

            // Parse and return the first Verifiable Credential as SignedJWT
            return SignedJWT.parse((String) firstCredential);

        } catch (ParseException e) {
            throw new JWTParsingException("Error parsing the Verifiable Presentation or Verifiable Credential");
        }
    }

    private static Object getVcClaim(Object vpClaim) {
        if (vpClaim == null) {
            throw new JWTClaimMissingException("The 'vp' claim was not found in the Verifiable Presentation");
        }
        // Ensure that vpClaim is an instance of Map (JSON object)
        if (!(vpClaim instanceof Map<?, ?> vpMap)) {
            throw new JWTClaimMissingException("The 'vp' claim is not a valid object");
        }
        // Extract the "verifiableCredential" claim inside "vp"
        Object vcClaim = vpMap.get("verifiableCredential");
        if (vcClaim == null) {
            throw new JWTClaimMissingException("The 'verifiableCredential' claim was not found within 'vp'");
        }
        return vcClaim;
    }


    private static Object getFirstCredential(Object vcClaim) {
        if (!(vcClaim instanceof List<?> verifiableCredentials)) {
            throw new CredentialException("The verifiableCredential claim is not an array");
        }
        if (verifiableCredentials.isEmpty()) {
            throw new CredentialException("No Verifiable Credential found in Verifiable Presentation");
        }
        // Ensure the first item is a String (JWT in string form)
        Object firstCredential = verifiableCredentials.get(0);
        if (!(firstCredential instanceof String)) {
            throw new CredentialException("The first Verifiable Credential is not a valid JWT string");
        }
        return firstCredential;
    }

    private String extractDidFromKidIssSub(String kid, String iss, String sub) {
        if (kid != null && kid.startsWith("did:")) {
            return kid.contains("#") ? kid.substring(0, kid.indexOf('#')) : kid;
        }
        if (iss != null && iss.startsWith("did:")) return iss;
        if (sub != null && sub.startsWith("did:")) return sub;
        return null;
    }

    private String extractBoundDidFromCredential(LEARCredential cred, String vcSub) {
        // 1) NEW: credentialSubject.id (preferred)
        String csId = safeGetCredentialSubjectId(cred);
        csId = normalizeDid(csId);
        if (csId != null && !csId.isBlank()) {

            if (vcSub != null && vcSub.startsWith("did:") && !csId.equals(vcSub)) {
                log.warn("[BIND] VC mismatch: credentialSubject.id={} != vcSub={}", csId, vcSub);
            }

            return csId;
        }

        // 2) NEW: VC JWT sub
        if (vcSub != null && vcSub.startsWith("did:")) return vcSub;

        // 3) LEGACY: mandatee.id
        String mandateeId = normalizeDid(cred.mandateeId());
        if (mandateeId != null && !mandateeId.isBlank()) return mandateeId;

        return null;
    }

    private String normalizeDid(String did) {
        if (did == null) return null;
        if (!did.startsWith("did:")) return did;
        return did.contains("#") ? did.substring(0, did.indexOf('#')) : did;
    }

    private String safeGetCredentialSubjectId(LEARCredential cred) {
        try {
            return cred.credentialSubjectId();
        } catch (Exception ignore) {
            return null;
        }
    }


}