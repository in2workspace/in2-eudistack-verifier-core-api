package es.in2.vcverifier.service.impl;

import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.exception.*;
import es.in2.vcverifier.model.StatusListCredentialData;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.service.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

@Service
@RequiredArgsConstructor
@Slf4j
public class TrustFrameworkServiceImpl implements TrustFrameworkService {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final CertificateValidationService certificateValidationService;
    private final StatusListCredentialService statusListCredentialService;
    private final HttpClient httpClient;
    private final TrustedIssuersProvider trustedIssuersProvider;
    @Override
    public List<IssuerCredentialsCapabilities> getTrustedIssuerListData(String id) {
        return trustedIssuersProvider.getIssuerCapabilities(id);
    }

    @Override
    public boolean isCredentialRevokedInBitstringStatusList(
            String statusListCredentialUrl,
            String statusListIndex,
            String credentialStatusPurpose) {

        log.info("Checking credential revocation in bitstring status list - URL: {}, Index: {}, Purpose: {}",
                statusListCredentialUrl, statusListIndex, credentialStatusPurpose);

        // Parse and validate the status list index
        final int index = parseAndValidateStatusListIndex(statusListIndex);

        // Fetch the Status List Credential JWT
        final String jwtString = fetchStatusListCredentialJwt(statusListCredentialUrl);

        log.debug("Status List Credential JWT fetched successfully");

        final SignedJWT signedJwt = parseSignedJwt(jwtString);
        // Validate the certificate of the Status List Credential
        validateStatusListCredentialCertificate(jwtString, signedJwt);

        // Parse the JWT using StatusListCredentialService
        final StatusListCredentialData statusData = statusListCredentialService.parse(signedJwt);

        log.debug("Status List Credential parsed successfully. Purpose: {}", statusData.statusPurpose());

        // Validate that the status purpose matches
        statusListCredentialService.validateStatusPurposeMatches(
                statusData.statusPurpose(),
                credentialStatusPurpose
        );

        // Check if the index is within bounds
        final int maxBits = statusListCredentialService.maxBits(statusData.rawBitstringBytes());
        if (index >= maxBits) {
            throw new CredentialException(
                    "statusListIndex out of range. maxBits=" + maxBits + ", index=" + index
            );
        }

        // Check if the bit at the given index is set (credential is revoked/suspended)
        final boolean isRevoked = statusListCredentialService.isBitSet(statusData.rawBitstringBytes(), index);

        log.info("Credential revocation check completed. Index: {}, IsRevoked: {}", index, isRevoked);

        return isRevoked;
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
            throw new IllegalStateException("Failed to gunzip content", e);
        }
    }


    /**
     * Decodes the encodedList (multibase base64url gzip) into raw bitstring bytes.
     */
    private byte[] decodeEncodedListToRawBytes(String encodedList) {
        log.info("decodeEncodedListToRawBytes - encodedList: " + encodedList);
        if (encodedList == null || encodedList.isBlank()) {
            throw new CredentialException("encodedList cannot be blank");
        }

        String payload = encodedList.trim();

        if (payload.charAt(0) != 'u') {
            throw new CredentialException("encodedList must start with multibase base64url prefix 'u'");
        }

        payload = payload.substring(1);
        log.info("decodeEncodedListToRawBytes - extracted payload: " + payload);

        final byte[] gzipped;
        try {
            gzipped = Base64.getUrlDecoder().decode(payload);
        } catch (IllegalArgumentException e) {
            throw new CredentialException("encodedList is not valid base64url" + e.getMessage());
        }
        log.info("gzipped: {}", gzipped);

        return gunzip(gzipped);
    }

    private int parseAndValidateStatusListIndex(String statusListIndex) {
        final int index;
        try {
            index = Integer.parseInt(statusListIndex);
        } catch (NumberFormatException e) {
            throw new CredentialException(
                    "statusListIndex " + statusListIndex + "is not a valid integer: " + e.getMessage()
            );
        }

        if (index < 0) {
            throw new CredentialException("statusListIndex must be >= 0, but was: " + statusListIndex);
        }

        return index;
    }

    private String fetchStatusListCredentialJwt(String statusListCredentialUrl) {
        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(statusListCredentialUrl))
                .header("Accept", "application/vc+jwt")
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();

        final HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new FailedCommunicationException(
                    "Interrupted while fetching Status List Credential from: " + statusListCredentialUrl + ". " +  e
            );
        } catch (IOException e) {
            throw new FailedCommunicationException(
                    "Error fetching Status List Credential from: " + statusListCredentialUrl + ". " + e
            );
        }

        if (response.statusCode() == 404) {
            throw new FailedCommunicationException(
                    "Status List Credential not found at: " + statusListCredentialUrl
            );
        }

        if (response.statusCode() != 200) {
            throw new FailedCommunicationException(
                    "Failed to fetch Status List Credential. Status code: " + response.statusCode()
                            + ", URL: " + statusListCredentialUrl
            );
        }

        return response.body();
    }

    private void validateStatusListCredentialCertificate(String jwtString, SignedJWT signedJwt) {
        final Map<String, Object> vcHeader = signedJwt.getHeader().toJSONObject();

        final String credentialIssuerDid;
        try {
            credentialIssuerDid = signedJwt.getJWTClaimsSet().getStringClaim("issuer");
        } catch (ParseException e) {
            throw new CredentialException("Error reading JWT claims: " + e.getMessage());
        }

        if (credentialIssuerDid == null || credentialIssuerDid.isBlank()) {
            throw new CredentialException("Missing or blank 'issuer' claim in Status List Credential JWT");
        }

        if (!credentialIssuerDid.startsWith("did:elsi:")) {
            throw new CredentialException("Unsupported issuer DID format. Expected 'did:elsi:...' but got: " + credentialIssuerDid);
        }

        final String certificateId = credentialIssuerDid.substring("did:elsi:".length());

        certificateValidationService.extractAndVerifyCertificate(jwtString, vcHeader, certificateId);

        log.debug("Status List Credential certificate validated successfully for issuer: {}", credentialIssuerDid);
    }

    private SignedJWT parseSignedJwt(String jwtString) {
        try {
            return SignedJWT.parse(jwtString);
        } catch (ParseException e) {
            throw new CredentialException("Error parsing Status List Credential JWT: " + e.getMessage());
        }
    }

}



