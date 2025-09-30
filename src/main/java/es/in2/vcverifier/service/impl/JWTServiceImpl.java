package es.in2.vcverifier.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.component.CryptoComponent;
import es.in2.vcverifier.exception.JWTClaimMissingException;
import es.in2.vcverifier.exception.JWTCreationException;
import es.in2.vcverifier.exception.JWTParsingException;
import es.in2.vcverifier.exception.JWTVerificationException;
import es.in2.vcverifier.service.DIDService;
import es.in2.vcverifier.service.JWTService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.text.ParseException;
import java.util.Base64;
import java.util.Map;

import static es.in2.vcverifier.util.Constants.OID4VP_TYPE;

@Slf4j
@Service
@RequiredArgsConstructor
public class JWTServiceImpl implements JWTService {

    private final CryptoComponent cryptoComponent;
    private final ObjectMapper objectMapper;
    private final DIDService didService;

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
        log.info("Raw JWT received = {}", jwt);
        try {
            // 0) Tipus correcte i cast
            if (!(publicKey instanceof ECPublicKey)) {
                throw new IllegalArgumentException("Invalid key type for EC verification");
            }
            ECPublicKey ecProvided = (ECPublicKey) publicKey;
            printPublicKeyAsJwk(ecProvided); // opcional: per debug

            // 1) Parse JWT + logs bàsics
            SignedJWT sjwt = SignedJWT.parse(jwt);
            JWSHeader hdr = sjwt.getHeader();
            String kid = hdr.getKeyID();

            System.out.println("ALG = " + hdr.getAlgorithm());
            System.out.println("KID = " + kid);
            System.out.println("Signature length (JOSE r||s) = " + sjwt.getSignature().decode().length);
            log.info("JWT header  = {}", sjwt.getHeader().toJSONObject());
            log.info("JWT payload = {}", sjwt.getPayload().toString());
            log.info("JWT signature (b64u) = {}", sjwt.getSignature().toString());
            // 2) Si el KID és un did:key, resol la clau i compara x/y
            if (kid != null && kid.startsWith("did:key:")) {
                PublicKey kidPk = didService.getPublicKeyFromDid(kid);
                if (!(kidPk instanceof ECPublicKey)) {
                    throw new IllegalStateException("DID resolved key is not EC");
                }
                ECPublicKey ecFromDid = (ECPublicKey) kidPk;

                // compara corba i punt (x/y)
                boolean same = sameEcPublicKey(ecFromDid, ecProvided);
                if (!same) {
                    throw new JWTVerificationException("Public key mismatch: KID key and provided key differ (X/Y).");
                }
            }

            //2.2
            String token = jwt;                       // el que reps
            int lastDot = token.lastIndexOf('.');
            String inputFromToken = token.substring(0, lastDot);   // headerB64u.payloadB64u tal qual
            String inputFromNimbus = new String(((com.nimbusds.jose.JWSObject) sjwt).getSigningInput(), java.nio.charset.StandardCharsets.US_ASCII);

            System.out.println("same signing input? " + inputFromToken.equals(inputFromNimbus));


            // 3. signingInput = headerB64u + "." + payloadB64u (exactament com al token)
            byte[] signingInput = ((com.nimbusds.jose.JWSObject) sjwt).getSigningInput();
            // signatura JOSE (P1363 r||s, 64 bytes per ES256)
            byte[] sig = sjwt.getSignature().decode();

            Signature s = Signature.getInstance("SHA256withECDSAinP1363Format"); // JDK 11+
            s.initVerify((ECPublicKey) publicKey);
            s.update(signingInput);
            boolean okJdk = s.verify(sig);
            System.out.println("JDK P1363 verify = " + okJdk);

            // 4) Verificació ES256 amb la clau proporcionada
            JWSVerifier verifier = new ECDSAVerifier(ecProvided);
            if (!sjwt.verify(verifier)) {
                throw new JWTVerificationException("Invalid JWT signature for EC key");
            }

        } catch (Exception e) {
            log.error("Exception during JWT signature verification with EC key", e);
            throw new JWTVerificationException("JWT signature verification failed due to unexpected error: " + e.getMessage());
        }
    }


    private static byte[] toUnsignedFixed(BigInteger bi, int sizeBytes) {
        byte[] raw = bi.toByteArray();                 // pot venir amb byte de signe
        if (raw.length == sizeBytes) return raw;
        byte[] out = new byte[sizeBytes];
        int srcPos = Math.max(0, raw.length - sizeBytes);
        int len = Math.min(sizeBytes, raw.length);
        System.arraycopy(raw, srcPos, out, sizeBytes - len, len);
        return out;
    }

    private static int fieldSizeBytes(ECPublicKey k) {
        return (k.getParams().getCurve().getField().getFieldSize() + 7) / 8;
    }

    /** Retorna x/y en Base64URL (com en un JWK) per una ECPublicKey. */
    private static String[] jwkXY(ECPublicKey k) {
        ECPoint w = k.getW();
        int size = fieldSizeBytes(k);
        String xB64u = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(toUnsignedFixed(w.getAffineX(), size));
        String yB64u = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(toUnsignedFixed(w.getAffineY(), size));
        return new String[]{xB64u, yB64u};
    }

    /** Compara dues ECPublicKey: mateixa corba i mateix punt. Logueja detalls. */
    private static boolean sameEcPublicKey(ECPublicKey a, ECPublicKey b) {
        int sa = a.getParams().getCurve().getField().getFieldSize();
        int sb = b.getParams().getCurve().getField().getFieldSize();
        if (sa != sb) {
            System.out.println("Curve mismatch: field sizes " + sa + " vs " + sb);
            return false;
        }
        ECPoint wa = a.getW(), wb = b.getW();
        boolean same = wa.getAffineX().equals(wb.getAffineX()) && wa.getAffineY().equals(wb.getAffineY());
        String[] A = jwkXY(a), B = jwkXY(b);
        System.out.println("KEY A JWK = {\"kty\":\"EC\",\"crv\":\"P-" + sa + "\",\"x\":\"" + A[0] + "\",\"y\":\"" + A[1] + "\"}");
        System.out.println("KEY B JWK = {\"kty\":\"EC\",\"crv\":\"P-" + sb + "\",\"x\":\"" + B[0] + "\",\"y\":\"" + B[1] + "\"}");
        System.out.println("Same curve bits? " + (sa == sb) + " | Same X/Y? " + same);
        return same;
    }

    private static void printPublicKeyAsJwk(ECPublicKey ec) {
        int size = (ec.getParams().getCurve().getField().getFieldSize() + 7) / 8; // 32 per P-256
        var p = ec.getW();
        String xB64u = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(toUnsignedFixed(p.getAffineX(), size));
        String yB64u = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(toUnsignedFixed(p.getAffineY(), size));
        System.out.println("VERIFY KEY JWK = {\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\""+xB64u+"\",\"y\":\""+yB64u+"\"}");
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
            return jwt.serialize();
        } catch (JOSEException e) {
            log.error("JWTServiceImpl -- generateJWT -- Error during JWT creation", e);
            throw new JWTCreationException("Error creating JWT");
        }
    }
    //todo remove
    private static String convertToPEM(PublicKey publicKey) {
        String base64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n"
                + base64.replaceAll("(.{64})", "$1\n")
                + "\n-----END PUBLIC KEY-----";
    }
}
