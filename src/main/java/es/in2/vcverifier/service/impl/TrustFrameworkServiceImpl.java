package es.in2.vcverifier.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.config.BackendConfig;
import es.in2.vcverifier.dto.CredentialStatusResponse;
import es.in2.vcverifier.exception.*;
import es.in2.vcverifier.model.ExternalTrustedListYamlData;
import es.in2.vcverifier.model.RevokedCredentialIds;
import es.in2.vcverifier.model.issuer.IssuerAttribute;
import es.in2.vcverifier.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.model.issuer.IssuerResponse;
import es.in2.vcverifier.service.CertificateValidationService;
import es.in2.vcverifier.service.TrustFrameworkService;
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
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.zip.GZIPInputStream;

@Service
@RequiredArgsConstructor
@Slf4j
public class TrustFrameworkServiceImpl implements TrustFrameworkService {

    private final ObjectMapper objectMapper;
    private final BackendConfig backendConfig;
    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
    private final CertificateValidationService certificateValidationService;

    @Override
    public ExternalTrustedListYamlData fetchAllowedClient() {
        try {
            String clientsYaml = fetchRemoteFile(backendConfig.getClientsRepositoryUri());
            return yamlMapper.readValue(clientsYaml, ExternalTrustedListYamlData.class);
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RemoteFileFetchException("Error reading clients list from GitHub.", e);
        }
    }

    @Override
    public List<IssuerCredentialsCapabilities> getTrustedIssuerListData(String id) {
        try {
            // Step 1: Send HTTP request to fetch issuer data
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(backendConfig.getTrustedIssuerListUri() + id))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                // Step 2: Map response to IssuerResponse object
                IssuerResponse issuerResponse = objectMapper.readValue(response.body(), IssuerResponse.class);

                // Step 3: Decode and map each attribute's body to IssuerCredentialsCapabilities
                return issuerResponse.attributes().stream()
                        .map(this::decodeAndMapIssuerAttributeBody)
                        .toList();
            } else if (response.statusCode() == 404) {
                throw new IssuerNotAuthorizedException("Issuer with id: " + id + " not found.");
            } else {
                throw new IOException("Failed to fetch issuer data. Status code: " + response.statusCode());
            }
        } catch (IssuerNotAuthorizedException e) {
            log.error("Issuer not found: {}", e.getMessage());
            throw e;
        } catch (IOException | InterruptedException e) {
            log.error("Error fetching issuer data for id {}: {}", id, e.getMessage());
            Thread.currentThread().interrupt();
            throw new FailedCommunicationException("Error fetching issuer data");
        }
    }

    public List<String> getCredentialStatusListData(String url) {
        try {
            // Step 1: Send HTTP request to fetch issuer data
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                return objectMapper.readValue(response.body(), new TypeReference<List<CredentialStatusResponse>>() {})
                        .stream()
                        .map(CredentialStatusResponse::credentialNonce)
                        .collect(Collectors.toList());
            } else if (response.statusCode() == 404) {
                throw new IOException("Credential List with url: " + url + " not found.");
            } else {
                throw new IOException("Failed to fetch credential data. Status code: " + response.statusCode());
            }
        } catch (IOException | InterruptedException e) {
            log.error("Error fetching credential status data for url {}: {}", url, e.getMessage());
            Thread.currentThread().interrupt();
            throw new FailedCommunicationException("Error fetching credential status data");
        }
    }

    @Override
    public List<String> getRevokedCredentialIds() {
        try {
            String revokedCredentialIdsYaml = fetchRemoteFile(backendConfig.getRevocationListUri());
            RevokedCredentialIds revokedCredentialIds = yamlMapper.readValue(revokedCredentialIdsYaml, RevokedCredentialIds.class);
            return revokedCredentialIds.revokedCredentials();
        } catch (IOException | InterruptedException e) {
            log.error("Error fetching revoked credential IDs from URI {}: {}", backendConfig.getRevocationListUri(), e.getMessage());
            Thread.currentThread().interrupt();
            throw new FailedCommunicationException("Error fetching revoked credential IDs: " + e.getMessage());
        }
    }

    @Override
    public boolean isCredentialRevokedInBitstringStatusList(String statusListCredentialUrl, String statusListIndex, String credentialStatusPurpose) {
        log.info("isCredentialRevokedInBitstringStatusList, statusListCredentialUrl: {}, statusListIndex: {}, credentialStatusPurpose: {}", statusListCredentialUrl, statusListIndex, credentialStatusPurpose);
        final int index;
        try {
            index = Integer.parseInt(statusListIndex);
        } catch (NumberFormatException e) {
            throw new CredentialException("statusListIndex is not a valid integer: " + statusListIndex + e.getMessage());
        }

        if (index < 0) {
            throw new CredentialException("statusListIndex must be >= 0: " + statusListIndex);
        }

        final HttpClient client = HttpClient.newHttpClient();
        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(statusListCredentialUrl))
                .header("Accept", "application/vc+jwt")
                .GET()
                .build();

        final HttpResponse<String> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new FailedCommunicationException("Interrupted while fetching Status List Credential" + e.getMessage());
        } catch (IOException e) {
            throw new FailedCommunicationException("Error fetching Status List Credential" + e.getMessage());
        }

        if (response.statusCode() == 404) {
            throw new FailedCommunicationException("Status List Credential not found: " + statusListCredentialUrl);
        }

        if (response.statusCode() != 200) {
            throw new FailedCommunicationException(
                    "Failed to fetch Status List Credential. Status code: " + response.statusCode()
            );
        }

        try {
            // Body is the JWT string when using application/vc+jwt
            String jwtString = response.body();
            log.info("body response: {}", jwtString);
            //todo validate with jwtService.verifyJWTWithX5cRS256(jwtString);

            SignedJWT signedJWTCredential = SignedJWT.parse(jwtString);

            Map<String, Object> vcHeader = signedJWTCredential.getHeader().toJSONObject();

            // Read issuer from claims (payload)
            String credentialIssuerDid;
            try {
                credentialIssuerDid = signedJWTCredential.getJWTClaimsSet().getStringClaim("issuer");
            } catch (ParseException e) {
                throw new CredentialException("Error reading JWT claims: " + e.getMessage());
            }

            if (credentialIssuerDid == null || credentialIssuerDid.isBlank()) {
                throw new CredentialException("Missing or blank 'issuer' claim in Status List Credential JWT");
            }

            if (!credentialIssuerDid.startsWith("did:elsi:")) {
                throw new CredentialException("Unsupported issuer DID format: " + credentialIssuerDid);
            }

            certificateValidationService.extractAndVerifyCertificate(
                    signedJWTCredential.serialize(),
                    vcHeader,
                    credentialIssuerDid.substring("did:elsi:".length())
            );


            JsonNode claims = objectMapper.valueToTree(signedJWTCredential.getJWTClaimsSet().toJSONObject());
            log.info("Claims: " + claims);

            String statusListCredentialPurpose = extractStatusPurposeFromStatusListCredentialClaims(claims);
            log.info("Extracted statusListCredential purpose: " + statusListCredentialPurpose);
            if(!statusListCredentialPurpose.equals(credentialStatusPurpose)){
                throw new CredentialException("Status status purpose of the credential being validated and the status purpose from the statusListCredential don't match: " + credentialStatusPurpose + ", " + statusListCredentialPurpose);
            }

            String encodedList = extractEncodedListFromStatusListCredentialClaims(claims);
            log.info("Extracted encodedList: " + encodedList);

            byte[] rawBytes = decodeEncodedListToRawBytes(encodedList);

            // Optional but strongly recommended: bounds check to fail fast
            int maxBits = rawBytes.length * 8;
            if (index >= maxBits) {
                throw new CredentialException("statusListIndex out of range. maxBits=" + maxBits + ", index=" + index);
            }

            return isBitSet(rawBytes, index);

        } catch (CredentialException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialException("Error processing bitstring status list credential: " + e.getMessage());
        }
    }


    // Helper method to decode Base64 and map to IssuerCredentialsCapabilities
    private IssuerCredentialsCapabilities decodeAndMapIssuerAttributeBody(IssuerAttribute issuerAttribute) {
        try {
            // Decode the Base64 body
            String decodedBody = new String(Base64.getDecoder().decode(issuerAttribute.body()), StandardCharsets.UTF_8);

            // Map the decoded string to IssuerCredentialsCapabilities
            return objectMapper.readValue(decodedBody, IssuerCredentialsCapabilities.class);
        } catch (IOException e) {
            log.error("Failed to decode and map issuer attribute body: {}", e.getMessage());
            throw new JsonConversionException("Failed to decode and map issuer attribute body");
        }
    }

    private String fetchRemoteFile(String fileUrl) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(fileUrl))
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            return response.body();
        } else {
            throw new RemoteFileFetchException("Failed to fetch file from GitHub. Status code: " + response.statusCode());
        }
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
     * Extracts credentialSubject.statusPurpose from the JWT claims.
     */
    // todo avoid duplication
    // todo consider making statusListCredential an implementation of VerifiablCredential
    private String extractStatusPurposeFromStatusListCredentialClaims(JsonNode claims) {
        if (claims == null || claims.isNull()) {
            throw new CredentialException("Missing JWT claims");
        }

        JsonNode credentialSubject = claims.get("credentialSubject");
        if (credentialSubject == null || credentialSubject.isNull()) {
            throw new CredentialException("Missing 'credentialSubject' in Status List Credential JWT");
        }

        JsonNode statusPurpose = credentialSubject.get("statusPurpose");
        if (statusPurpose == null || !statusPurpose.isTextual() || statusPurpose.asText().isBlank()) {
            throw new CredentialException("Missing or invalid 'credentialSubject.statusPurpose' in Status List Credential JWT");
        }

        return statusPurpose.asText();
    }

    /**
     * Extracts credentialSubject.encodedList from the JWT claims.
     */
    private String extractEncodedListFromStatusListCredentialClaims(JsonNode claims) {
        if (claims == null || claims.isNull()) {
            throw new CredentialException("Missing JWT claims");
        }

        JsonNode credentialSubject = claims.get("credentialSubject");
        if (credentialSubject == null || credentialSubject.isNull()) {
            throw new CredentialException("Missing 'credentialSubject' in Status List Credential JWT");
        }

        JsonNode encodedList = credentialSubject.get("encodedList");
        if (encodedList == null || !encodedList.isTextual() || encodedList.asText().isBlank()) {
            throw new CredentialException("Missing or invalid 'credentialSubject.encodedList' in Status List Credential JWT");
        }

        return encodedList.asText();
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


    /**
     * Bit numbering is LSB-first within each byte, matching the issuer implementation.
     */
    private boolean isBitSet(byte[] rawBytes, int bitIndex) {
        log.info("isBitSet");
        if (rawBytes == null) {
            throw new IllegalArgumentException("rawBytes cannot be null");
        }
        if (bitIndex < 0) {
            throw new IllegalArgumentException("bitIndex must be >= 0");
        }

        int maxBits = rawBytes.length * 8;
        if (bitIndex >= maxBits) {
            throw new IllegalArgumentException("bitIndex out of range. maxBits=" + maxBits + ", bitIndex=" + bitIndex);
        }

        int byteIndex = bitIndex / 8;
        int bitInByte = bitIndex % 8;

        int mask = 1 << bitInByte;
        return (rawBytes[byteIndex] & mask) != 0;
    }

}




