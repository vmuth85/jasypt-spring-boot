package com.ulisesbocchio.jasyptspringboot.resolver;

import com.ulisesbocchio.jasyptspringboot.caching.CachingDelegateEncryptablePropertySource;
import org.jasypt.encryption.StringEncryptor;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MapPropertySource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Verifies that a nested encrypted lookup does not leave ciphertext in the property-source cache.
 *
 * @author 25.11.2026 by Viktor Muth - Cover decryption during re-entrant placeholder resolution.
 */
class DefaultPropertyResolverReentranceTest {

    /**
     * Unencrypted placeholders are returned in their original form by this resolver; the assertion that matters
     * here is that the encrypted value read during that lookup was not cached as ciphertext.
     */
    @Test
    void encryptedValueReadDuringPlaceholderResolutionIsCachedDecrypted() {
        Environment environment = mock(Environment.class);
        StringEncryptor encryptor = mock(StringEncryptor.class);
        DefaultPropertyResolver resolver = new DefaultPropertyResolver(encryptor, environment);
        MapPropertySource delegate = new MapPropertySource("environment", Map.of(
                "trigger", "${trigger}",
                "secret", "ENC(cipher)"));
        CachingDelegateEncryptablePropertySource<Map<String, Object>> propertySource =
                new CachingDelegateEncryptablePropertySource<>(delegate, resolver, (source, name) -> true);

        when(encryptor.decrypt("cipher")).thenReturn("cleartext");
        when(environment.resolvePlaceholders(anyString())).thenAnswer(invocation -> {
            String value = invocation.getArgument(0);
            if ("${trigger}".equals(value)) {
                propertySource.getProperty("secret");
                return "resolved";
            }
            return value;
        });

        assertEquals("${trigger}", propertySource.getProperty("trigger"));
        assertEquals("cleartext", propertySource.getProperty("secret"));
    }
}
