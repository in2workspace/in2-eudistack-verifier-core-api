package es.in2.vcverifier.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.exception.*;
import es.in2.vcverifier.model.credentials.lear.LEARCredential;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV1;
import es.in2.vcverifier.model.credentials.lear.employee.LEARCredentialEmployeeV2;
import es.in2.vcverifier.model.credentials.lear.machine.LEARCredentialMachine;
import es.in2.vcverifier.model.enums.LEARCredentialType;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.service.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.text.ParseException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
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
    public boolean validateVerifiablePresentation(String verifiablePresentation) {
        log.info("Starting validation of Verifiable Presentation");
        try {
            // Step 1: Extract the Verifiable Credential (VC) from the VP (JWT)
            log.debug("VpServiceImpl -- validateVerifiablePresentation -- Extracting first Verifiable Credential from Verifiable Presentation");
            SignedJWT jwtCredential = extractFirstVerifiableCredential(verifiablePresentation);
            Payload payload = jwtService.getPayloadFromSignedJWT(jwtCredential);
            log.debug("VpServiceImpl -- validateVerifiablePresentation -- Successfully extracted the Verifiable Credential payload");

            // Step 1.1: Map the payload to a VerifiableCredential object
            LEARCredential learCredential = mapPayloadToVerifiableCredential(payload);

            // Step 2: Validate the time window of the credential
            log.debug("VpServiceImpl -- validateVerifiablePresentation -- Validating the time window of the credential");
            validateCredentialTimeWindow(learCredential);

            // Step 3: Validate the credential id is not in the revoked list
            log.debug("VpServiceImpl -- validateVerifiablePresentation -- Validating that the credential is not revoked");
            validateCredentialNotRevoked(learCredential.id());
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

            // Step 10: Validate the VP's signature with the DIDService (the DID of the holder of the VP)
            String mandateeId = learCredential.mandateeId();
            PublicKey holderPublicKey = didService.getPublicKeyFromDid(mandateeId); // Get the holder's public key in bytes
            jwtService.verifyJWTWithECKey(verifiablePresentation, holderPublicKey); // Validate the VP was signed by the holder DID
            log.info("VP's signature is valid, holder DID {} confirmed", mandateeId);

            log.info("Verifiable Presentation validation completed successfully");
            return true; // All validations passed
        } catch (Exception e) {
            log.error("Error during VP validation: {}", e.getMessage());
            return false;
        }
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
        if (types.contains(LEARCredentialType.LEAR_CREDENTIAL_EMPLOYEE.getValue())) {
            // Extract the '@context' field from the VC
            List<String> contextList = extractContext(vcMap);

            // Compare the context with the v1 and v2 constants
            if (contextList.equals(LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT)) {
                return objectMapper.convertValue(vcMap, LEARCredentialEmployeeV1.class);
            } else if (contextList.equals(LEAR_CREDENTIAL_EMPLOYEE_V2_CONTEXT)) {
                return objectMapper.convertValue(vcMap, LEARCredentialEmployeeV2.class);
            } else {
                throw new InvalidCredentialTypeException("Unknown LEARCredentialEmployee version: " + contextList);
            }
        } else if (types.contains(LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue())) {
            return objectMapper.convertValue(vcMap, LEARCredentialMachine.class);
        } else {
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

    private void validateCredentialNotRevoked(String credentialId) {
        List<String> revokedIds = trustFrameworkService.getRevokedCredentialIds();
        if (revokedIds.contains(credentialId)) {
            throw new CredentialRevokedException("Credential ID " + credentialId + " is revoked.");
        }

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
}