package es.in2.vcverifier.shared.crypto;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;

import java.security.PublicKey;

public interface JWTService {

    String generateJWT(String payload);

    void verifyJWTWithECKey(String jwt, PublicKey publicKey);

    SignedJWT parseJWT(String jwt);

    Payload getPayloadFromSignedJWT(SignedJWT signedJWT);

    String getClaimFromPayload(Payload payload, String claimName);

    long getExpirationFromPayload(Payload payload);

    Object getVCFromPayload(Payload payload);

    String generateJWTwithOI4VPType(String s);
}
