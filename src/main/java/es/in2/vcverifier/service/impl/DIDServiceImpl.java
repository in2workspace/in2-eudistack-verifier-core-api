package es.in2.vcverifier.service.impl;

import es.in2.vcverifier.exception.PublicKeyDecodingException;
import es.in2.vcverifier.exception.UnsupportedDIDTypeException;
import es.in2.vcverifier.service.DIDService;
import io.github.novacrypto.base58.Base58;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class DIDServiceImpl implements DIDService {

    @Override
    public PublicKey getPublicKeyFromDid(String did) {
        log.info("Attempting to retrieve public key from DID: {}", did);
        if (!did.startsWith("did:key:")) {
            log.error("DIDServiceImpl -- getPublicKeyFromDid -- Unsupported DID format detected: {}", did);
            throw new UnsupportedDIDTypeException("Unsupported DID type. Only did:key is supported for the moment.");
        }

        // Remove the "did:key:" prefix to get the actual encoded public key
        String encodedPublicKey = did.substring("did:key:".length());
        log.debug("DIDServiceImpl -- getPublicKeyFromDid -- Encoded public key extracted from DID: {}", encodedPublicKey);

        // Decode the public key from its encoded representation
        return decodePublicKeyIntoPubKey(encodedPublicKey);
    }

    private PublicKey decodePublicKeyIntoPubKey(String encodePublicKey) {
        log.info("Decoding public key from encoded string: {}", encodePublicKey);

        try {
            // 0) Multibase: esperem Base58btc amb prefix 'z'
            if (encodePublicKey == null || !encodePublicKey.startsWith("z")) {
                throw new PublicKeyDecodingException("Invalid Public Key: expected multibase Base58btc (starts with 'z').");
            }
            String multibaseEncoded = encodePublicKey.substring(1);

            // 1) Base58 decode
            byte[] decodedBytes = Base58.base58Decode(multibaseEncoded);
            if (decodedBytes == null || decodedBytes.length < 35) { // 2 bytes (varint) + 33 bytes (punt comprimit)
                throw new PublicKeyDecodingException("Decoded key too short");
            }

            // 2) Llegeix el multicodec com UNSIGNED VARINT (LEB128)
            int idx = 0, shift = 0, code = 0;
            while (true) {
                int b = decodedBytes[idx++] & 0xFF;
                code |= (b & 0x7F) << shift;
                if ((b & 0x80) == 0) break;   // aquest byte tanca el varint
                shift += 7;
                if (idx >= decodedBytes.length || shift > 28) {
                    throw new PublicKeyDecodingException("Invalid multicodec varint");
                }
            }
            log.info(String.format("Multicodec code = 0x%04X", code));

            // 3) Valida que sigui P-256 public key (p256-pub = 0x1200)
            final int P256_PUB = 0x1200;
            if (code != P256_PUB) {
                throw new PublicKeyDecodingException(
                        String.format("Unexpected multicodec: 0x%04X (expected p256-pub 0x1200)", code)
                );
            }

            // 4) La resta són els bytes del punt EC en format SEC1 comprimit (33 bytes: 0x02/0x03 + X)
            byte[] publicKeyBytes = Arrays.copyOfRange(decodedBytes, idx, decodedBytes.length);
            if (publicKeyBytes.length != 33) {
                throw new PublicKeyDecodingException("Unexpected EC point length (expected 33 bytes compressed)");
            }

            int prefix = publicKeyBytes[0] & 0xFF;
            if (prefix != 0x02 && prefix != 0x03) {
                throw new PublicKeyDecodingException(
                        String.format("Unexpected EC point format: 0x%02X (expected 0x02/0x03 compressed)", prefix)
                );
            }

            // 5) Reconstrueix coordenades amb la corba secp256r1 (P-256)
            ECCurve curve = new SecP256R1Curve();
            // X són els 32 bytes següents (sense signe)
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(publicKeyBytes, 1, 33));
            // Y es recupera decodificant el punt comprimit
            BigInteger y = curve.decodePoint(publicKeyBytes).getYCoord().toBigInteger();

            log.info("DID key point X = {}", x);
            log.info("DID key point Y = {}", y);

            // (Opcional) imprimeix en JWK per comparar amb JWKS/DID Document
            int size = 32; // P-256
            String xB64u = Base64.getUrlEncoder().withoutPadding().encodeToString(toUnsignedFixed(x, size));
            String yB64u = Base64.getUrlEncoder().withoutPadding().encodeToString(toUnsignedFixed(y, size));
            log.info("DID key JWK = {{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{}\",\"y\":\"{}\"}}", xB64u, yB64u);

            // 6) Construeix la PublicKey Java
            ECPoint point = new ECPoint(x, y);
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            ECNamedCurveSpec params = new ECNamedCurveSpec("secp256r1", ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN());

            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey pk = kf.generatePublic(new ECPublicKeySpec(point, params));
            log.info("Public key successfully decoded and generated: {}", pk);
            return pk;

        } catch (Exception e) {
            log.error("DIDServiceImpl -- decodePublicKeyIntoPubKey -- Failed to decode and generate public key: {}", e.getMessage(), e);
            throw new PublicKeyDecodingException("JWT signature verification failed.", e);
        }
    }

    /** Zero-pad/trim to unsigned fixed length (p.ex. 32 bytes per P-256). */
    private static byte[] toUnsignedFixed(BigInteger bi, int sizeBytes) {
        byte[] raw = bi.toByteArray(); // pot portar byte de signe
        if (raw.length == sizeBytes) return raw;
        byte[] out = new byte[sizeBytes];
        int srcPos = Math.max(0, raw.length - sizeBytes);
        int len = Math.min(sizeBytes, raw.length);
        System.arraycopy(raw, srcPos, out, sizeBytes - len, len);
        return out;
    }



}
