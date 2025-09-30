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
            // Remove the prefix "z" to get the multibase encoded string
            if (!encodePublicKey.startsWith("z")) {
                log.error("DIDServiceImpl -- decodePublicKeyIntoPubKey -- Invalid public key format detected: {}", encodePublicKey);
                throw new PublicKeyDecodingException("Invalid Public Key.");
            }
            String multibaseEncoded = encodePublicKey.substring(1);

            // Multibase decode (Base58) the encoded part to get the bytes
            byte[] decodedBytes = Base58.base58Decode(multibaseEncoded);
            if (decodedBytes.length < 35) {
                throw new PublicKeyDecodingException("Decoded key too short");
            }
            // 2. comprova multicodec
            if ((decodedBytes[0] & 0xFF) != 0x12 || (decodedBytes[1] & 0xFF) != 0x00) {
                throw new PublicKeyDecodingException(
                        String.format("Unexpected multicodec prefix: 0x%02X%02X (not P-256)", decodedBytes[0], decodedBytes[1])
                );
            }
            byte[] publicKeyBytesArr = Arrays.copyOfRange(decodedBytes, 2, decodedBytes.length);
            // 3. comprova prefix SEC1 comprimit: 0x02 o 0x03
            int yParity = publicKeyBytesArr[0] & 0xFF;
            if (yParity != 0x02 && yParity != 0x03) {
                throw new PublicKeyDecodingException(
                        String.format("Unexpected EC point format: 0x%02X (expected 0x02/0x03 compressed)", yParity)
                );
            }
            log.debug("DIDServiceImpl -- decodePublicKeyIntoPubKey -- Decoded bytes from Base58: {}", Arrays.toString(decodedBytes));

            // Multicodec prefix is fixed for "0x1200" for the secp256r1 curve
            int prefixLength = 2;

            // Extract public key bytes after the multicodec prefix
            byte[] publicKeyBytes = new byte[decodedBytes.length - prefixLength];
            System.arraycopy(decodedBytes, prefixLength, publicKeyBytes, 0, publicKeyBytes.length);

            // Set the curve as secp256r1
            ECCurve curve = new SecP256R1Curve();
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(publicKeyBytes, 1, publicKeyBytes.length));

            // Recover the Y coordinate from the X coordinate and the curve
            BigInteger y = curve.decodePoint(publicKeyBytes).getYCoord().toBigInteger();
            log.info("DID key point X = {}", x);
            log.info("DID key point Y = {}", y);

            log.debug("DIDServiceImpl -- decodePublicKeyIntoPubKey -- Calculated ECPoint coordinates - X: {}, Y: {}", x, y);
            ECPoint point = new ECPoint(x, y);

            // Fetch the ECParameterSpec for secp256r1
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            ECNamedCurveSpec params = new ECNamedCurveSpec("secp256r1", ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN());

            // Create a KeyFactory and generate the public key
            KeyFactory kf = KeyFactory.getInstance("EC");
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);

            log.info("Public key successfully decoded and generated: {}", kf.generatePublic(pubKeySpec));
            return kf.generatePublic(pubKeySpec);
        }
        catch (Exception e) {
            log.error("DIDServiceImpl -- decodePublicKeyIntoPubKey -- Failed to decode and generate public key: {}", e.getMessage(), e);
            throw new PublicKeyDecodingException("JWT signature verification failed.", e);
        }
    }


}
