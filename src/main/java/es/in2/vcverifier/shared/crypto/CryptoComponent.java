package es.in2.vcverifier.shared.crypto;

import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.domain.exception.ECKeyCreationException;
import io.github.novacrypto.base58.Base58;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class CryptoComponent {

    private final BackendConfig backendConfig;

    @Bean
    public ECKey getECKey() {
        if (backendConfig.hasIdentityConfigured()) {
            log.info("Building EC key from configured private key");
            return buildEcKeyFromPrivateKey();
        }
        log.warn("No private key configured — generating ephemeral P-256 key pair. "
                + "This is suitable for development only. Configure verifier.backend.identity.privateKey for production.");
        return generateEphemeralEcKey();
    }

    private ECKey buildEcKeyFromPrivateKey() {
        try {
            BigInteger privateKeyInt = new BigInteger(backendConfig.getPrivateKey(), 16);
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProviderSingleton.getInstance());

            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKeyInt, ecSpec);
            ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);

            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecSpec.getG().multiply(privateKeyInt), ecSpec);
            ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);

            String didKey = backendConfig.getDidKey();
            if (didKey == null || didKey.isBlank()) {
                didKey = deriveDidKey(publicKey);
                log.info("Derived did:key from configured private key: {}", didKey);
            }

            return new ECKey.Builder(Curve.P_256, publicKey)
                    .privateKey(privateKey)
                    .keyID(didKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .build();
        } catch (Exception e) {
            throw new ECKeyCreationException("Error creating JWK source for secp256r1: " + e);
        }
    }

    private ECKey generateEphemeralEcKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
            var keyPair = keyPairGenerator.generateKeyPair();

            ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
            ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

            String didKey = deriveDidKey(publicKey);
            log.warn("Generated ephemeral P-256 key. did:key:{}", didKey);

            return new ECKey.Builder(Curve.P_256, publicKey)
                    .privateKey(privateKey)
                    .keyID(didKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .build();
        } catch (Exception e) {
            throw new ECKeyCreationException("Error generating ephemeral P-256 key pair: " + e);
        }
    }

    /**
     * Derives a did:key from a P-256 public key.
     * Format: did:key:z{base58btc(multicodec_prefix + compressed_pubkey)}
     * Multicodec for P-256: 0x1200 (varint: 0x80 0x24)
     */
    static String deriveDidKey(ECPublicKey publicKey) {
        byte[] compressed = compressPublicKey(publicKey);

        // Multicodec prefix for P-256 public key: 0x1200 as varint = [0x80, 0x24]
        byte[] multicodecPrefix = new byte[]{(byte) 0x80, (byte) 0x24};
        byte[] multicodecKey = new byte[multicodecPrefix.length + compressed.length];
        System.arraycopy(multicodecPrefix, 0, multicodecKey, 0, multicodecPrefix.length);
        System.arraycopy(compressed, 0, multicodecKey, multicodecPrefix.length, compressed.length);

        // Base58btc with 'z' prefix (multibase convention)
        String encoded = "z" + Base58.base58Encode(multicodecKey);

        return "did:key:" + encoded;
    }

    private static byte[] compressPublicKey(ECPublicKey publicKey) {
        byte[] x = normalizeTo32Bytes(publicKey.getW().getAffineX().toByteArray());
        byte[] y = publicKey.getW().getAffineY().toByteArray();

        byte prefix = (y[y.length - 1] & 1) == 0 ? (byte) 0x02 : (byte) 0x03;
        byte[] compressed = new byte[33];
        compressed[0] = prefix;
        System.arraycopy(x, 0, compressed, 1, 32);
        return compressed;
    }

    private static byte[] normalizeTo32Bytes(byte[] input) {
        if (input.length == 32) return input;
        byte[] result = new byte[32];
        if (input.length > 32) {
            // Strip leading zero(s)
            System.arraycopy(input, input.length - 32, result, 0, 32);
        } else {
            // Pad with leading zeros
            System.arraycopy(input, 0, result, 32 - input.length, input.length);
        }
        return result;
    }
}
