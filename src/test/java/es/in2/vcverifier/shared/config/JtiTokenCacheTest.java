package es.in2.vcverifier.shared.config;
import es.in2.vcverifier.shared.config.JtiTokenCache;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

class JtiTokenCacheTest {

    private JtiTokenCache jtiTokenCache;

    @BeforeEach
    void setUp() {
        jtiTokenCache = new JtiTokenCache(new HashSet<>());
    }

    @Test
    void isJtiPresent_empty_returnsFalse() {
        assertFalse(jtiTokenCache.isJtiPresent("jti-1"));
    }

    @Test
    void addJti_thenIsPresent_returnsTrue() {
        jtiTokenCache.addJti("jti-1");
        assertTrue(jtiTokenCache.isJtiPresent("jti-1"));
    }

    @Test
    void addJti_duplicateDoesNotFail() {
        jtiTokenCache.addJti("jti-1");
        jtiTokenCache.addJti("jti-1");
        assertTrue(jtiTokenCache.isJtiPresent("jti-1"));
    }

    @Test
    void isJtiPresent_differentJti_returnsFalse() {
        jtiTokenCache.addJti("jti-1");
        assertFalse(jtiTokenCache.isJtiPresent("jti-2"));
    }
}
