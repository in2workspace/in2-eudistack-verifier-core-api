package es.in2.vcverifier.util;

import java.util.List;

public class Constants {
    private Constants() {
        throw new IllegalStateException("Utility class");
    }

    public static final String CLIENT_ID = "client_id";
    public static final String REQUEST_URI = "request_uri";
    public static final String REQUEST = "request";
    public static final String RESPONSE_TYPE= "response_type";
    public static final String SCOPE = "scope";
    public static final String AUTHORIZATION_RESPONSE_ENDPOINT= "/oid4vp/auth-response";
    public static final String DID_ELSI_PREFIX = "did:elsi:";
    public static final String MINUTES = "MINUTES";
    public static final String LOGIN_ENDPOINT = "/login";
    public static final String CLIENT_ERROR_ENDPOINT = "/client-error";
    public static final String REQUIRED_EXTERNAL_USER_AUTHENTICATION = "required_external_user_authentication";
    public static final String INVALID_CLIENT_AUTHENTICATION = "invalid_client_authentication";
    public static final String LOG_ERROR_FORMAT = "{} - {}";
    // ACCESS_TOKEN_EXPIRATION_TIME must be in seconds
    public static final String ACCESS_TOKEN_EXPIRATION_TIME = "3600";
    public static final String ACCESS_TOKEN_EXPIRATION_CHRONO_UNIT = "SECONDS";
    // ID_TOKEN_EXPIRATION_TIME  must be in seconds
    public static final String ID_TOKEN_EXPIRATION_TIME = "60";
    public static final String ID_TOKEN_EXPIRATION_CHRONO_UNIT = "SECONDS";
    // LOGIN_TIMEOUT must be in seconds
    public static final String LOGIN_TIMEOUT = "120";
    public static final String LOGIN_TIMEOUT_CHRONO_UNIT = "SECONDS";
    public static final boolean IS_NONCE_REQUIRED_ON_FAPI_PROFILE = false;
    public static final List<String> LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT = List.of("https://www.w3.org/ns/credentials/v2","https://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1");
    public static final List<String> LEAR_CREDENTIAL_EMPLOYEE_V2_CONTEXT = List.of("https://www.w3.org/ns/credentials/v2","https://www.dome-marketplace.eu/2025/credentials/learcredentialemployee/v2");
    public static final long MSB = 0x80L;
    public static final long MSBALL = 0xFFFFFF80L;
    public static final String EXPIRATION = "expiration";


}
