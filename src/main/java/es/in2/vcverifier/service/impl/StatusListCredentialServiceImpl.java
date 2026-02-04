package es.in2.vcverifier.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.exception.StatusListCredentialException;
import es.in2.vcverifier.model.StatusListCredentialData;
import es.in2.vcverifier.service.StatusListCredentialService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.ParseException;
import java.util.Base64;
import java.util.zip.GZIPInputStream;

@Slf4j
@RequiredArgsConstructor
@Service
public class StatusListCredentialServiceImpl implements StatusListCredentialService {

    private final ObjectMapper objectMapper;

    @Override
    public void validateStatusPurposeMatches(String statusListCredentialPurpose, String expectedPurpose) {
        log.debug("Validating statusPurpose match. expectedPurpose='{}', statusListCredentialPurpose='{}'",
                expectedPurpose, statusListCredentialPurpose);

        if (expectedPurpose == null || expectedPurpose.isBlank()) {
            log.warn("Expected statusPurpose is missing or blank");
            throw new StatusListCredentialException("Expected statusPurpose cannot be blank");
        }

        if (statusListCredentialPurpose == null || statusListCredentialPurpose.isBlank()) {
            log.warn("Status List Credential statusPurpose is missing or blank");
            throw new StatusListCredentialException("Status List Credential statusPurpose cannot be blank");
        }

        if (!statusListCredentialPurpose.equals(expectedPurpose)) {
            log.warn("StatusPurpose mismatch. expected='{}', actual='{}'",
                    expectedPurpose, statusListCredentialPurpose);
            throw new StatusListCredentialException(
                    "StatusPurpose mismatch. expected=" + expectedPurpose + ", actual=" + statusListCredentialPurpose
            );
        }

        log.debug("StatusPurpose match OK. purpose='{}'", expectedPurpose);
    }

    @Override
    public StatusListCredentialData parse(String jwtString) {
        log.debug("Parsing Status List Credential from JWT string. jwtLength={}", jwtString == null ? null : jwtString.length());

        try {
            SignedJWT signedJwt = SignedJWT.parse(jwtString);
            log.debug("JWT string parsed to SignedJWT successfully");
            return parse(signedJwt);
        } catch (ParseException e) {
            log.warn("Failed to parse JWT string into SignedJWT", e);
            throw new StatusListCredentialException(
                    "Error parsing Status List Credential JWT", e
            );
        } catch (RuntimeException e) {
            log.warn("Unexpected error while parsing JWT string into SignedJWT", e);
            throw e;
        }
    }

    @Override
    public StatusListCredentialData parse(SignedJWT signedJwt) {
        log.debug("Parsing Status List Credential from SignedJWT. signedJwtNull={}", signedJwt == null);

        try {
            JsonNode claimsNode = objectMapper.valueToTree(
                    signedJwt.getJWTClaimsSet().toJSONObject()
            );
            JsonNode credentialSubject = getRequiredObject(claimsNode, "credentialSubject");
            log.debug("credentialSubject extracted. fields={}", credentialSubject.size());

            String statusPurpose = getRequiredText(credentialSubject, "statusPurpose");

            String encodedList = getRequiredText(credentialSubject, "encodedList");

            byte[] rawBitstringBytes = decodeEncodedListToRawBytes(encodedList);

            String issuer = signedJwt.getJWTClaimsSet().getIssuer();

            return new StatusListCredentialData(
                    issuer,
                    statusPurpose,
                    rawBitstringBytes
            );

        } catch (ParseException e) {
            log.warn("Failed to read JWT claims from SignedJWT", e);
            throw new StatusListCredentialException(
                    "Error reading Status List Credential JWT claims", e
            );
        }
    }

    public boolean isBitSet(byte[] rawBytes, int bitIndex) {
        log.debug("Checking if bit is set. rawBytesNull={}, bitIndex={}", rawBytes == null, bitIndex);

        if (rawBytes == null) {
            log.warn("rawBytes is null in isBitSet");
            throw new StatusListCredentialException("rawBytes cannot be null");
        }
        if (bitIndex < 0) {
            log.warn("bitIndex is negative in isBitSet. bitIndex={}", bitIndex);
            throw new StatusListCredentialException("bitIndex must be >= 0");
        }

        int maxBits = rawBytes.length * 8;
        if (bitIndex >= maxBits) {
            log.warn("bitIndex out of range in isBitSet. maxBits={}, bitIndex={}", maxBits, bitIndex);
            throw new StatusListCredentialException(
                    "bitIndex out of range. maxBits=" + maxBits + ", bitIndex=" + bitIndex
            );
        }

        int byteIndex = bitIndex / 8; // Use MSB-first bit ordering within each byte: bitIndex 0
        int bitInByte = 7 - (bitIndex % 8);
        int mask = 1 << bitInByte;

        boolean result = (rawBytes[byteIndex] & mask) != 0;
        log.debug("Bit check computed. byteIndex={}, bitInByte={}, mask={}, result={}", byteIndex, bitInByte, mask, result);

        return result;
    }

    public int maxBits(byte[] rawBytes) {

        if (rawBytes == null) {
            log.warn("rawBytes is null in maxBits");
            throw new StatusListCredentialException("rawBytes cannot be null");
        }
        return rawBytes.length * 8;
    }

    // ------------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------------

    private JsonNode getRequiredObject(JsonNode parent, String field) {

        if (parent == null || parent.isNull()) {
            log.warn("Missing JWT claims when reading required object field '{}'", field);
            throw new StatusListCredentialException("Missing JWT claims");
        }
        JsonNode node = parent.get(field);
        if (node == null || node.isNull() || !node.isObject()) {
            log.warn("Missing or invalid object field '{}'. nodeNull={}, nodeIsNull={}, nodeIsObject={}",
                    field, node == null, node != null && node.isNull(), node != null && node.isObject());
            throw new StatusListCredentialException("Missing or invalid '" + field + "'");
        }
        return node;
    }

    private String getRequiredText(JsonNode parent, String field) {
        JsonNode node = parent.get(field);
        if (node == null || !node.isTextual() || node.asText().isBlank()) {
            log.warn("Missing or invalid text field '{}'. nodeNull={}, nodeIsTextual={}, textBlank={}",
                    field,
                    node == null,
                    node != null && node.isTextual(),
                    node != null && node.isTextual() && node.asText().isBlank());
            throw new StatusListCredentialException("Missing or invalid '" + field + "'");
        }
        return node.asText();
    }

    private byte[] decodeEncodedListToRawBytes(String encodedList) {
        log.debug("Decoding encodedList to raw bytes. encodedListNull={}, encodedListBlank={}",
                encodedList == null, encodedList != null && encodedList.isBlank());

        if (encodedList == null || encodedList.isBlank()) {
            log.warn("encodedList is null or blank");
            throw new StatusListCredentialException("encodedList cannot be blank");
        }

        String payload = encodedList.trim();

        if (payload.charAt(0) != 'u') {
            log.warn("encodedList does not start with multibase base64url prefix 'u'. firstChar='{}'",
                    payload.isEmpty() ? null : payload.charAt(0));
            throw new StatusListCredentialException(
                    "encodedList must start with multibase base64url prefix 'u'"
            );
        }

        final byte[] gzipped;
        try {
            gzipped = Base64.getUrlDecoder().decode(payload.substring(1));
        } catch (IllegalArgumentException e) {
            log.warn("encodedList is not valid base64url", e);
            throw new StatusListCredentialException("encodedList is not valid base64url", e);
        }

        return gunzip(gzipped);
    }

    private byte[] gunzip(byte[] input) {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(input);
             GZIPInputStream gzip = new GZIPInputStream(bais);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[8 * 1024];
            int read;

            while ((read = gzip.read(buffer)) != -1) {
                baos.write(buffer, 0, read);
            }

            return baos.toByteArray();
        } catch (IOException e) {
            log.warn("Failed to gunzip content. inputLength={}", input == null ? null : input.length, e);
            throw new StatusListCredentialException("Failed to gunzip content", e);
        }
    }
}
