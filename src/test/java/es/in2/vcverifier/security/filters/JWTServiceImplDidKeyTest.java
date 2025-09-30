package es.in2.vcverifier.security.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.exception.JWTVerificationException;
import es.in2.vcverifier.service.JWTService;
import es.in2.vcverifier.service.impl.JWTServiceImpl;
import io.github.novacrypto.base58.Base58;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class JWTServiceImplDidKeyTest {

    private JWTService jwtService;

    //TOKEN DE REQUEST .JWT
    private static final String JWT =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDprZXk6ekRuYWVjTWM1WUVTOTE3Rk1lN3pKR2dtcGE0dHRHWVZjakJjVkVjNm84RmdmY0tENyJ9."
                    + "eyJpc3MiOiJkaWQ6a2V5OnpEbmFlY01jNVlFUzkxN0ZNZTd6SkdnbXBhNHR0R1lWY2pCY1ZFYzZvOEZnZmNLRDciLCJhdWQiOiJodHRwczovL3ZlcmlmaWVyLmRvbWUtbWFya2V0cGxhY2UtbGNsLm9yZy8iLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6ImRpZDprZXk6ekRuYWVjTWM1WUVTOTE3Rk1lN3pKR2dtcGE0dHRHWVZjakJjVkVjNm84RmdmY0tENyIsInJlZGlyZWN0X3VyaSI6Imh0dHBzOi8vZG9tZS50ZGRldi5pdC9hdXRoL3ZjL2NhbGxiYWNrIiwic2NvcGUiOiJvcGVuaWQgbGVhcmNyZWRlbnRpYWwiLCJpYXQiOjE3NTkxNTQ4NDJ9."
                    + "4khIdOoxlL9uF91gyjx55RK_vtzJHBGiJ423vMO_cVM8zyVPEe0iW1JLi0gOzl9N6jjNbHmdLrrXHU9mD_KU6A";

    //DID-KEY QUE ES PASSA A LA URL (CLIENT_ID)
    private static final String DID_KEY =
            "did:key:zDnaecMc5YES917FMe7zJGgmpa4ttGYVcjBcVEc6o8FgfcKD7";

    @BeforeEach
    void setUp() {
        jwtService = new JWTServiceImpl(null, new ObjectMapper());
    }

    @Disabled("Posa-hi la teva private key PKCS#8 (PEM o Base64 DER) i el DID real, després treu @Disabled")
    @Test
    void verifyJWTWithECKey_passes_withGivenDidKey() throws Exception {
        PublicKey ecPublicKey = ecPublicKeyFromDidKey(DID_KEY);
        assertInstanceOf(ECPublicKey.class, ecPublicKey);
        assertDoesNotThrow(() -> jwtService.verifyJWTWithECKey(JWT, ecPublicKey));
    }

    @Test
    void verifyJWTWithECKey_fails_whenSignatureIsTampered() throws Exception {
        PublicKey ecPublicKey = ecPublicKeyFromDidKey(DID_KEY);

        String[] parts = JWT.split("\\.");
        assertEquals(3, parts.length);

        byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
        payload[0] ^= 0x01; // flip 1 bit
        String badPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payload);

        String tampered = parts[0] + "." + badPayload + "." + parts[2];

        assertThrows(JWTVerificationException.class,
                () -> jwtService.verifyJWTWithECKey(tampered, ecPublicKey));
    }

    /** TEST: comprova que la private key correspon al seu did:key (round-trip generant un parell nou). */
    @Test
    void privateKeyMatchesDidKey_roundTrip() throws Exception {
        // 1) Generem parell EC P-256
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();
        ECPrivateKey ecPrivateKey = (ECPrivateKey) kp.getPrivate();
        ECPublicKey ecPublicKey = (ECPublicKey) kp.getPublic();

        // 2) Construeix el did:key a partir de la pública
        String didFromPublic = didKeyFromECPublicKey(ecPublicKey);

        // 3) Deriva la pública a partir de la privada i compara amb la del did:key
        PublicKey derivedPub = ecPublicKeyFromPrivate(ecPrivateKey);
        PublicKey fromDid = ecPublicKeyFromDidKey(didFromPublic);

        assertArrayEquals(derivedPub.getEncoded(), fromDid.getEncoded(),
                "La pública derivada de la private key ha de coincidir amb la pública del did:key");
    }

    // NOTA MEVA: AIXÒ VALIDA UNA PRIVATE KEY CONTRA UN DID-KEY
    @Test
    void privateKeyMatchesGivenDidKey_realValues() throws Exception {
        // --- SUBSTITUEIX aquests valors pels teus ---
        String yourDidKey = DID_KEY; // canvia’l pel DID real si és un altre
        // Private key en PKCS#8. Accepta:
        // - PEM amb capçaleres -----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----
        // - Base64 DER sense capçaleres
        String yourPrivateKeyPemOrB64 = "";
        // ---------------------------------------------

        ECPrivateKey ecPrivateKey = loadEcPrivateKeyFlexible(yourPrivateKeyPemOrB64);
        PublicKey derivedPub = ecPublicKeyFromPrivate(ecPrivateKey);
        PublicKey fromDid = ecPublicKeyFromDidKey(yourDidKey);

        assertArrayEquals(derivedPub.getEncoded(), fromDid.getEncoded(),
                "Aquesta private key no correspon al did:key indicat");
    }

    /** did:key (base58btc) -> ECPublicKey (secp256r1, multicodec 0x1200, punt comprimit) */
    private static PublicKey ecPublicKeyFromDidKey(String didKey) throws Exception {
        if (!didKey.startsWith("did:key:")) {
            throw new IllegalArgumentException("did:key invàlid");
        }
        String mb = didKey.substring("did:key:".length());
        if (!mb.startsWith("z")) {
            throw new IllegalArgumentException("Multibase no suportada (cal prefix 'z' base58btc)");
        }

        byte[] multicodecBytes = Base58.base58Decode(mb.substring(1));

        Varint v = readUVarint(multicodecBytes, 0);
        int code = v.value;
        int offset = v.bytesRead;
        if (code != 0x1200) {
            throw new IllegalArgumentException("Multicodec inesperat: 0x" + Integer.toHexString(code) + " (esperava 0x1200 p256-pub)");
        }

        byte[] compressedPoint = new byte[multicodecBytes.length - offset];
        System.arraycopy(multicodecBytes, offset, compressedPoint, 0, compressedPoint.length);

        ECNamedCurveParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECPoint bcPoint = bcSpec.getCurve().decodePoint(compressedPoint);

        java.security.spec.ECPoint w = new java.security.spec.ECPoint(
                bcPoint.getAffineXCoord().toBigInteger(),
                bcPoint.getAffineYCoord().toBigInteger()
        );

        ECNamedCurveSpec jceParams = new ECNamedCurveSpec(
                "secp256r1",
                bcSpec.getCurve(),
                bcSpec.getG(),
                bcSpec.getN(),
                bcSpec.getH(),
                bcSpec.getSeed()
        );

        ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, jceParams);
        return KeyFactory.getInstance("EC").generatePublic(pubSpec);
    }

    /** ECPublicKey <- ECPrivateKey (Q = d·G) */
    private static PublicKey ecPublicKeyFromPrivate(ECPrivateKey ecPrivateKey) throws Exception {
        ECNamedCurveParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        BigInteger d = ecPrivateKey.getS();
        ECPoint q = bcSpec.getG().multiply(d).normalize();

        java.security.spec.ECPoint w = new java.security.spec.ECPoint(
                q.getAffineXCoord().toBigInteger(),
                q.getAffineYCoord().toBigInteger()
        );

        ECNamedCurveSpec jceParams = new ECNamedCurveSpec(
                "secp256r1",
                bcSpec.getCurve(),
                bcSpec.getG(),
                bcSpec.getN(),
                bcSpec.getH(),
                bcSpec.getSeed()
        );

        ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, jceParams);
        return KeyFactory.getInstance("EC").generatePublic(pubSpec);
    }

    /** did:key <- ECPublicKey (multicodec 0x1200 + punt comprimit, multibase base58btc amb 'z') */
    private static String didKeyFromECPublicKey(ECPublicKey pub) {
        ECNamedCurveParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec("secp256r1");

        // Construeix punt BC i comprimeix-lo
        BigInteger x = pub.getW().getAffineX();
        BigInteger y = pub.getW().getAffineY();
        ECPoint bcPoint = bcSpec.getCurve().createPoint(x, y);
        byte[] compressed = bcPoint.getEncoded(true); // punt comprimit

        // Prefix multicodec (varint) per p256-pub (0x1200)
        byte[] prefix = writeUVarint(0x1200);

        byte[] multicodec = new byte[prefix.length + compressed.length];
        System.arraycopy(prefix, 0, multicodec, 0, prefix.length);
        System.arraycopy(compressed, 0, multicodec, prefix.length, compressed.length);

        return "did:key:z" + Base58.base58Encode(multicodec);
    }

    /** Carrega una EC Private Key PKCS#8 (PEM amb capçaleres o Base64 DER plana). */
    private static ECPrivateKey loadEcPrivateKeyFlexible(String input) throws Exception {
        String v = input.trim();

        // 1) HEX cru? (0x... o sense) — 32 bytes => 64 hex chars
        String hex = v.startsWith("0x") || v.startsWith("0X") ? v.substring(2) : v;
        if (hex.matches("(?i)^[0-9a-f]{64}$")) {
            // decodifica scalar d i construeix ECPrivateKeySpec amb P-256
            byte[] dBytes = hexStringToBytes(hex);
            BigInteger d = new BigInteger(1, dBytes);

            var bcSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1");
            var jceParams = new org.bouncycastle.jce.spec.ECNamedCurveSpec(
                    "secp256r1", bcSpec.getCurve(), bcSpec.getG(), bcSpec.getN(), bcSpec.getH(), bcSpec.getSeed()
            );

            ECPrivateKeySpec spec = new ECPrivateKeySpec(d, jceParams);
            return (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(spec);
        }

        // 2) PKCS#8 PEM?
        if (v.contains("BEGIN PRIVATE KEY")) {
            String b64 = v.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(b64);
            return (ECPrivateKey) KeyFactory.getInstance("EC")
                    .generatePrivate(new PKCS8EncodedKeySpec(der));
        }

        // 3) PKCS#8 DER Base64 "pla"?
        try {
            byte[] der = Base64.getDecoder().decode(v);
            return (ECPrivateKey) KeyFactory.getInstance("EC")
                    .generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (IllegalArgumentException e) {
            // No semblava Base64 vàlid
        }

        throw new InvalidKeyException("Format de clau privada no reconegut: usa hex (32 bytes) o PKCS#8 (PEM/DER).");
    }

    private static byte[] hexStringToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /** Varint (LEB128 sense signe) usat per multicodec. */
    private static Varint readUVarint(byte[] bytes, int pos) {
        long x = 0;
        int s = 0;
        int i = pos;
        while (i < bytes.length) {
            int b = bytes[i] & 0xFF;
            if (b < 0x80) {
                if (s >= 64) throw new IllegalArgumentException("varint overflow");
                return new Varint((int) (x | ((long) b << s)), (i - pos) + 1);
            }
            x |= (long) (b & 0x7F) << s;
            s += 7;
            i++;
        }
        throw new IllegalArgumentException("EOF llegint varint");
    }

    /** Escriu varint (LEB128 sense signe). */
    private static byte[] writeUVarint(int value) {
        int v = value;
        byte[] tmp = new byte[5]; // suficient per valors petits com 0x1200
        int idx = 0;
        while ((v & ~0x7F) != 0) {
            tmp[idx++] = (byte) ((v & 0x7F) | 0x80);
            v >>>= 7;
        }
        tmp[idx++] = (byte) v;
        byte[] out = new byte[idx];
        System.arraycopy(tmp, 0, out, 0, idx);
        return out;
    }

    private static class Varint { final int value, bytesRead; Varint(int v, int br){ value=v; bytesRead=br; } }
}