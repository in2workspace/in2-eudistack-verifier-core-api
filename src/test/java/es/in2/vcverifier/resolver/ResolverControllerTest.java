package es.in2.vcverifier.resolver;

import es.in2.vcverifier.config.FrontendConfig;
import es.in2.vcverifier.config.I18nConfig;
import es.in2.vcverifier.controller.ResolverController;
import es.in2.vcverifier.service.DIDService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.Base64;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(
        controllers = ResolverController.class,
        excludeFilters = @ComponentScan.Filter(
                type = FilterType.ASSIGNABLE_TYPE,
                classes = I18nConfig.class
        )
)
@AutoConfigureMockMvc(addFilters = false)  // Disable security filters for the test
class ResolverControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DIDService didService;

    @MockBean
    private FrontendConfig frontendConfig;

    @BeforeEach
    void setUp() {
        when(frontendConfig.getDefaultLang()).thenReturn("en");
    }

    @Test
    void testResolveDid() throws Exception {
        // Mock a public EC key
        ECPublicKey mockPublicKey = mock(ECPublicKey.class);
        ECPoint mockECPoint = new ECPoint(new BigInteger("12345"), new BigInteger("67890"));
        Mockito.when(mockPublicKey.getW()).thenReturn(mockECPoint);
        Mockito.when(didService.getPublicKeyFromDid("test-id")).thenReturn(mockPublicKey);

        // Perform GET request and verify response
        mockMvc.perform(get("/oidc/did/test-id"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("EC"))
                .andExpect(jsonPath("$.keys[0].crv").value("P-256"))
                .andExpect(jsonPath("$.keys[0].kid").value("test-id"))
                .andExpect(jsonPath("$.keys[0].x").exists())
                .andExpect(jsonPath("$.keys[0].y").exists());

        // Verify interactions with the service
        verify(didService, times(1)).getPublicKeyFromDid("test-id");
    }

    @Test
    void resolveDid_exact32BytesCoordinates_success() throws Exception {
        byte[] exact32 = new byte[32];

        Arrays.fill(exact32, (byte) 1);

        BigInteger x = new BigInteger(1, exact32);
        BigInteger y = new BigInteger(1, exact32);
        ECPoint point = new ECPoint(x, y);

        ECPublicKey mockPublicKey = mock(ECPublicKey.class);
        when(mockPublicKey.getW()).thenReturn(point);
        when(didService.getPublicKeyFromDid("did-32")).thenReturn(mockPublicKey);

        mockMvc.perform(get("/oidc/did/did-32"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("EC"))
                .andExpect(jsonPath("$.keys[0].crv").value("P-256"))
                .andExpect(jsonPath("$.keys[0].kid").value("did-32"))
                .andExpect(jsonPath("$.keys[0].x").value(Base64.getUrlEncoder().withoutPadding().encodeToString(exact32)))
                .andExpect(jsonPath("$.keys[0].y").value(Base64.getUrlEncoder().withoutPadding().encodeToString(exact32)));
    }

    @Test
    void resolveDid_33BytesWithLeadingZero_success() throws Exception {
        byte[] array33 = new byte[33];
        array33[0] = 0;
        for (int i = 1; i < 33; i++) {
            array33[i] = (byte) (i + 10);
        }
        byte[] expected32 = new byte[32];
        System.arraycopy(array33, 1, expected32, 0, 32);

        BigInteger mockX = mock(BigInteger.class);
        when(mockX.toByteArray()).thenReturn(array33);
        BigInteger mockY = mock(BigInteger.class);
        when(mockY.toByteArray()).thenReturn(array33);

        ECPoint point = new ECPoint(mockX, mockY);

        ECPublicKey mockPublicKey = mock(ECPublicKey.class);
        when(mockPublicKey.getW()).thenReturn(point);
        when(didService.getPublicKeyFromDid("did-33")).thenReturn(mockPublicKey);

        mockMvc.perform(get("/oidc/did/did-33"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].x").value(Base64.getUrlEncoder().withoutPadding().encodeToString(expected32)))
                .andExpect(jsonPath("$.keys[0].y").value(Base64.getUrlEncoder().withoutPadding().encodeToString(expected32)));
    }

    @Test
    void resolveDid_CoordinateLessThan32Bytes_padsZeros_success() throws Exception {
        byte[] array10 = new byte[10];
        for (int i = 0; i < 10; i++) {
            array10[i] = (byte) (i + 1);
        }
        byte[] expected32 = new byte[32];
        System.arraycopy(array10, 0, expected32, 32 - 10, 10);

        BigInteger mockX = mock(BigInteger.class);
        when(mockX.toByteArray()).thenReturn(array10);
        BigInteger mockY = mock(BigInteger.class);
        when(mockY.toByteArray()).thenReturn(array10);

        ECPoint point = new ECPoint(mockX, mockY);

        ECPublicKey mockPublicKey = mock(ECPublicKey.class);
        when(mockPublicKey.getW()).thenReturn(point);
        when(didService.getPublicKeyFromDid("did-short")).thenReturn(mockPublicKey);

        mockMvc.perform(get("/oidc/did/did-short"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].x").value(Base64.getUrlEncoder().withoutPadding().encodeToString(expected32)))
                .andExpect(jsonPath("$.keys[0].y").value(Base64.getUrlEncoder().withoutPadding().encodeToString(expected32)));
    }

    @Test
    void resolveDid_coordinateTooLong_throwsException() throws Exception {
        byte[] tooLong = new byte[34];
        for (int i = 0; i < 34; i++) {
            tooLong[i] = (byte) (i + 1);
        }

        BigInteger mockX = mock(BigInteger.class);
        when(mockX.toByteArray()).thenReturn(tooLong);
        BigInteger mockY = mock(BigInteger.class);
        when(mockY.toByteArray()).thenReturn(tooLong);

        ECPoint point = new ECPoint(mockX, mockY);

        ECPublicKey mockPublicKey = mock(ECPublicKey.class);
        when(mockPublicKey.getW()).thenReturn(point);
        when(didService.getPublicKeyFromDid("did-long")).thenReturn(mockPublicKey);

        mockMvc.perform(get("/oidc/did/did-long"))
                .andExpect(status().isInternalServerError());
    }

}
