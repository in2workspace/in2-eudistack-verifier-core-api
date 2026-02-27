package es.in2.vcverifier.shared.config;
import es.in2.vcverifier.config.CacheStore;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class CacheStoreTest {

    private CacheStore<String> cache;

    @BeforeEach
    void setUp() {
        cache = new CacheStore<>(10, TimeUnit.MINUTES);
    }

    @Test
    void add_and_get_success() {
        cache.add("key1", "value1");
        assertEquals("value1", cache.get("key1"));
    }

    @Test
    void get_missingKey_throwsNoSuchElementException() {
        assertThrows(NoSuchElementException.class, () -> cache.get("nonexistent"));
    }

    @Test
    void delete_removesEntry() {
        cache.add("key1", "value1");
        cache.delete("key1");
        assertThrows(NoSuchElementException.class, () -> cache.get("key1"));
    }

    @Test
    void add_nullKey_returnsNull() {
        assertNull(cache.add(null, "value"));
    }

    @Test
    void add_blankKey_returnsNull() {
        assertNull(cache.add("  ", "value"));
    }

    @Test
    void add_nullValue_returnsNull() {
        assertNull(cache.add("key", null));
    }

    @Test
    void add_validEntry_returnsKey() {
        String result = cache.add("key1", "value1");
        assertEquals("key1", result);
    }

    @Test
    void add_overwritesExistingKey() {
        cache.add("key1", "first");
        cache.add("key1", "second");
        assertEquals("second", cache.get("key1"));
    }

    @Test
    void expiry_entryDisappearsAfterExpiry() throws InterruptedException {
        CacheStore<String> shortCache = new CacheStore<>(1, TimeUnit.SECONDS);
        shortCache.add("key1", "value1");
        assertEquals("value1", shortCache.get("key1"));

        Thread.sleep(1500);
        assertThrows(NoSuchElementException.class, () -> shortCache.get("key1"));
    }
}
