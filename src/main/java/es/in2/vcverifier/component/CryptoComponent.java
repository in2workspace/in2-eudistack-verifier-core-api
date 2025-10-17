package es.in2.vcverifier.component;

import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import es.in2.vcverifier.config.BackendConfig;
import es.in2.vcverifier.exception.ECKeyCreationException;
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
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class CryptoComponent {

    private final BackendConfig backendConfig;

    @Bean
    public ECKey getECKey() {
        return buildEcKeyFromPrivateKey();
    }

    /**
     * Documentation: <a href="https://connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-es256r-signature">JSON Web Token (JWT) with ES256K (secp256k1) signature</a>
     *
     * @return - ECKey
     */
    private ECKey buildEcKeyFromPrivateKey() {
        try {
            // Convert the private key from hexadecimal string to BigInteger
            BigInteger privateKeyInt = new BigInteger(backendConfig.getPrivateKey(), 16);
            // Get the curve parameters for secp256r1 (P-256)
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            // Initialize the key factory for EC algorithm
            KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
            // Create the private key spec for secp256r1
            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKeyInt, ecSpec);
            ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);
            // Generate the public key spec from the private key and curve parameters
            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecSpec.getG().multiply(privateKeyInt), ecSpec);
            ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);

            java.security.spec.ECPoint w = publicKey.getW();
            String xHex = w.getAffineX().toString(16);
            String yHex = w.getAffineY().toString(16);
            String priv = backendConfig.getPrivateKey();
            String masked = priv != null && priv.length()>8 ? "****" + priv.substring(priv.length()-8) : "****";

            log.debug("DID key: {}", backendConfig.getDidKey());
            log.debug("Public X (hex): 0x{}", xHex);
            log.debug("Public Y (hex): 0x{}", yHex);
            log.debug("Private (masked): {}", masked);

            // Build the ECKey using secp256r1 curve (P-256)
            return new ECKey.Builder(Curve.P_256, publicKey)
                    .privateKey(privateKey)
                    .keyID(backendConfig.getDidKey())
                    .keyUse(KeyUse.SIGNATURE)
                    .build();
        } catch (Exception e) {
            throw new ECKeyCreationException("Error creating JWK source for secp256r1: " + e);
        }
    }
}
