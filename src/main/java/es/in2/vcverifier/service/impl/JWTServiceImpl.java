package es.in2.vcverifier.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.component.CryptoComponent;
import es.in2.vcverifier.exception.JWTClaimMissingException;
import es.in2.vcverifier.exception.JWTCreationException;
import es.in2.vcverifier.exception.JWTParsingException;
import es.in2.vcverifier.exception.JWTVerificationException;
import es.in2.vcverifier.service.JWTService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.Map;

import static es.in2.vcverifier.util.Constants.OID4VP_TYPE;

@Slf4j
@Service
@RequiredArgsConstructor
public class JWTServiceImpl implements JWTService {

    private final CryptoComponent cryptoComponent;
    private final ObjectMapper objectMapper;

    @Override
    public String generateJWT(String payload) {
        log.info("Starting standard JWT generation. Payload: {}", payload);
        return generateJWTInternal(payload,JOSEObjectType.JWT);
    }

    private JWTClaimsSet convertPayloadToJWTClaimsSet(String payload) {
        try {
            JsonNode jsonNode = objectMapper.readTree(payload);
            Map<String, Object> claimsMap = objectMapper.convertValue(jsonNode, new TypeReference<>() {
            });
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
            for (Map.Entry<String, Object> entry : claimsMap.entrySet()) {
                builder.claim(entry.getKey(), entry.getValue());
            }
            return builder.build();
        } catch (JsonProcessingException e) {
            log.error("Error while parsing the JWT payload", e);
            throw new JWTCreationException("Error while parsing the JWT payload");
        }

    }

    @Override
    public void verifyJWTWithECKey(String jwt, PublicKey publicKey) {
        log.debug("verifyJWTWithECKey");
        log.debug("jwt {}", jwt);
        log.debug("publicKey {}", publicKey);

        try {
            // Ensure the provided key is of the correct type
            if (!(publicKey instanceof ECPublicKey)) {
                throw new IllegalArgumentException("Invalid key type for EC verification");
            }

            // Parse the JWT
            SignedJWT signedJWT = SignedJWT.parse(jwt);

            // Create the EC verifier
            JWSVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKey);

            // Verify the signature
            if (!signedJWT.verify(verifier)) {
                throw new JWTVerificationException("Invalid JWT signature for EC key");
            }

        } catch (Exception e) {
            log.error("Exception during JWT signature verification with EC key", e);
            throw new JWTVerificationException("JWT signature verification failed due to unexpected error: " + e);
        }
    }

    @Override
    public SignedJWT parseJWT(String jwt) {
        try {
            return SignedJWT.parse(jwt);
        } catch (ParseException e) {
            log.error("Error parsing JWT: {}", e.getMessage());
            throw new JWTParsingException("Error parsing JWT");
        }
    }

    @Override
    public Payload getPayloadFromSignedJWT(SignedJWT signedJWT) {
        return signedJWT.getPayload();
    }

    @Override
    public String getClaimFromPayload(Payload payload, String claimName) {
        String claimValue = (String) payload.toJSONObject().get(claimName);
        if (claimValue == null || claimValue.trim().isEmpty()) {
            log.error("JWTServiceImpl -- getClaimFromPayload -- Claim '{}' is missing or empty in the JWT payload", claimName);
            throw new JWTClaimMissingException(String.format("The '%s' claim is missing or empty in the JWT payload.", claimName));
        }
        return claimValue;
    }

    @Override
    public long getExpirationFromPayload(Payload payload) {
        log.info("Retrieving expiration ('exp') from JWT payload");
        Long exp = (Long) payload.toJSONObject().get("exp");
        if (exp == null || exp <= 0) {
            log.error("JWTServiceImpl -- getExpirationFromPayload -- Expiration claim ('exp') is missing or invalid in the JWT payload");
            throw new JWTClaimMissingException("The 'exp' (expiration) claim is missing or invalid in the JWT payload.");
        }
        log.debug("JWTServiceImpl -- getExpirationFromPayload -- Expiration claim ('exp') retrieved successfully: {}", exp);
        return exp;
    }

    @Override
    public Object getVCFromPayload(Payload payload) {
        log.info("Retrieving verifiable credential ('vc') from JWT payload");
        return payload.toJSONObject().get("vc");
    }

    @Override
    public String generateJWTwithOI4VPType(String payload) {
        log.info("Starting OID4VP JWT generation with typ={}. Payload: {}", OID4VP_TYPE, payload);
        return generateJWTInternal(payload,new JOSEObjectType(OID4VP_TYPE));
    }

    private String generateJWTInternal(String payload, JOSEObjectType type) {
        try {
            log.info("Starting JWT generation process");

            // Get ECKey
            ECKey ecJWK = cryptoComponent.getECKey();
            log.debug("JWTServiceImpl -- generateJWT -- ECKey obtained for signing: {}", ecJWK.getKeyID());

            // Set Header
            JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(cryptoComponent.getECKey().getKeyID())
                    .type(type)
                    .build();
            log.debug("JWTServiceImpl -- generateJWT -- JWT header set with algorithm: {}", JWSAlgorithm.ES256);

            // Set Payload
            JWTClaimsSet claimsSet = convertPayloadToJWTClaimsSet(payload);
            log.debug("JWTServiceImpl -- generateJWT -- JWT claims set created from payload: {}", claimsSet);

            // Create JWT for ES256R algorithm
            SignedJWT jwt = new SignedJWT(jwsHeader, claimsSet);
            // Sign with a private EC key
            JWSSigner signer = new ECDSASigner(ecJWK);
            jwt.sign(signer);
            log.info("JWT generated and signed successfully");
            log.debug("jwt, {}", jwt.serialize());
            return jwt.serialize();
        } catch (JOSEException e) {
            log.error("JWTServiceImpl -- generateJWT -- Error during JWT creation", e);
            throw new JWTCreationException("Error creating JWT");
        }
    }
}
