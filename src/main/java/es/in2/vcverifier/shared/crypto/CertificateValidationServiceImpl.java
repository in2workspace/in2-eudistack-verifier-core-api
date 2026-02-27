package es.in2.vcverifier.shared.crypto;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.domain.exception.JWTVerificationException;
import es.in2.vcverifier.shared.domain.exception.MismatchOrganizationIdentifierException;
import es.in2.vcverifier.shared.crypto.CertificateValidationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.springframework.stereotype.Service;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateValidationServiceImpl implements CertificateValidationService {
    @Override
    public void extractAndVerifyCertificate(String verifiableCredential, Map<String, Object> vcHeader, String expectedOrgId) {
        // Retrieve the x5c claim (certificate chain)
        Object x5cObj = vcHeader.get("x5c");

        if (!(x5cObj instanceof List<?> x5c)) {
            throw new IllegalArgumentException("The x5c claim is not a valid list");
        }

        if (x5c.isEmpty()) {
            throw new IllegalArgumentException("No certificate (x5c) found in JWT header");
        }

        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            for (Object certBase64Obj : x5c) {
                if (!(certBase64Obj instanceof String certBase64Str)) {
                    log.error("Invalid certificate format in x5c");
                    continue; // Skip invalid entries and continue with the next one
                }

                // Use the extracted method to process the certificate
                PublicKey publicKey = processCertificate(certBase64Str, expectedOrgId, certificateFactory);
                if (publicKey != null) {
                    verifyJWTWithRSAKey(verifiableCredential ,publicKey);
                    return;
                }
                // If the loop finishes without finding a match, throw an exception
                throw new MismatchOrganizationIdentifierException("Organization Identifier not found in certificates.");
            }
        } catch (CertificateException e) {
            log.error("Error initializing CertificateFactory: {}", e.getMessage());
        }

    }

    private static PublicKey processCertificate(String certBase64Str, String expectedOrgId, CertificateFactory certificateFactory) {
        try {
            // Decode each certificate
            byte[] certBytes = Base64.getDecoder().decode(certBase64Str);
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));

            // Extract the DN (Distinguished Name)
            X500Principal subject = certificate.getSubjectX500Principal();
            String distinguishedName = subject.getName();
            log.info("Extracted DN: {}", distinguishedName);

            // Try to extract the organizationIdentifier from the DN
            String orgIdentifierFromDN = extractOrganizationIdentifierFromDN(distinguishedName);
            if (orgIdentifierFromDN != null && orgIdentifierFromDN.equals(expectedOrgId)) {
                log.info("Found matching organization identifier in DN: {}", orgIdentifierFromDN);
                return certificate.getPublicKey(); // Return the public key of the matching certificate
            }
        } catch (CertificateException e) {
            log.error("Error processing certificate: {}", e.getMessage());
            // Continue to the next certificate in the list
        }
        return null; // Return null if no matching certificate is found
    }


    // Helper method to extract and decode the organizationIdentifier from the DN
    private static String extractOrganizationIdentifierFromDN(String distinguishedName) {
        log.info("Extracting organizationIdentifier from DN: {}", distinguishedName);

        // Use a regular expression to find the 2.5.4.97 OID in the DN
        Pattern pattern = Pattern.compile("2\\.5\\.4\\.97=#([0-9A-F]+)", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(distinguishedName);

        if (matcher.find()) {
            String hexValue = matcher.group(1);
            log.info("Extracted hex value for organizationIdentifier: {}", hexValue);

            // Decode the hex string properly as ASN.1 encoded value
            return decodeHexToReadableString(hexValue);
        } else {
            log.warn("OID 2.5.4.97 not found in DN: {}", distinguishedName);
        }
        return null; // Return null if organizationIdentifier is not found
    }

    private static String decodeHexToReadableString(String hexValue) {
        try {
            byte[] octets = hexStringToByteArray(hexValue);
            ASN1Primitive asn1Primitive = readAsn1Primitive(octets);
            if (asn1Primitive != null) {
                return asn1PrimitiveToString(asn1Primitive);
            }
        } catch (IOException e) {
            log.error("Error decoding hex value to readable string", e);
        }
        return null;
    }

    private static ASN1Primitive readAsn1Primitive(byte[] octets) throws IOException {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(octets))) {
            return asn1InputStream.readObject();
        }
    }

    private static String asn1PrimitiveToString(ASN1Primitive asn1Primitive) {
        if (asn1Primitive instanceof ASN1OctetString octetString) {
            return new String(octetString.getOctets(), StandardCharsets.UTF_8); // Try to decode as UTF-8
        } else if (asn1Primitive instanceof ASN1PrintableString asn1PrintableString) {
            return asn1PrintableString.getString();
        } else if (asn1Primitive instanceof ASN1UTF8String asn1UTF8String) {
            return asn1UTF8String.getString();
        } else if (asn1Primitive instanceof ASN1IA5String asn1IA5String) {
            return asn1IA5String.getString();
        } else {
            log.warn("Unrecognized ASN.1 type: {}", asn1Primitive.getClass().getSimpleName());
        }
        return null;
    }

    // Convert hex string to byte array
    private static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        if (len % 2 != 0) {
            log.error("Invalid hex string length");
            return new byte[0];
        }
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int high = Character.digit(hex.charAt(i), 16);
            int low = Character.digit(hex.charAt(i + 1), 16);
            if (high == -1 || low == -1) {
                log.error("Invalid hex character in string");
                return new byte[0];
            }
            data[i / 2] = (byte) ((high << 4) + low);
        }
        return data;
    }

    private void verifyJWTWithRSAKey(String jwt, PublicKey publicKey) {
        try {
            // Ensure the provided key is of the correct type
            if (!(publicKey instanceof RSAPublicKey)) {
                throw new IllegalArgumentException("Invalid key type for RSA verification");
            }

            // Parse the JWT
            SignedJWT signedJWT = SignedJWT.parse(jwt);

            // Define critical headers to defer
            Set<String> defCriticalHeaders = new HashSet<>();
            defCriticalHeaders.add("sigT");

            // Create a policy for critical header parameters and set the deferred ones
            CriticalHeaderParamsDeferral criticalPolicy = new CriticalHeaderParamsDeferral();
            criticalPolicy.setDeferredCriticalHeaderParams(defCriticalHeaders);

            // Create the RSA verifier
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey, defCriticalHeaders);

            // Verify the signature
            if (!signedJWT.verify(verifier)) {
                throw new JWTVerificationException("Invalid JWT signature for RSA key");
            }

        } catch (Exception e) {
            log.error("Exception during JWT signature verification with RSA key", e);
            throw new JWTVerificationException("JWT signature verification failed due to unexpected error: " + e);
        }
    }
}
