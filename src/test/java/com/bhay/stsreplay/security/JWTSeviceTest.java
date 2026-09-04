package com.bhay.stsreplay.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Plain unit test — no Spring context is started here. JwtService is instantiated
 * directly and its @Value-injected fields are set manually via ReflectionTestUtils,
 * since @Value only resolves inside a running Spring context. This keeps the test
 * fast and isolated to JwtService's own logic.
 *
 * Adjust the package declaration above if your JwtService lives somewhere else.
 */
class JwtServiceTest {

    private JwtService jwtService;

    private static final String TEST_SECRET =
            "this-is-a-test-secret-key-that-is-at-least-32-bytes-long";
    private static final long ONE_HOUR_MS = 3_600_000L;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "secret", TEST_SECRET);
        ReflectionTestUtils.setField(jwtService, "expirationMs", ONE_HOUR_MS);
    }

    @Test
    void generateToken_producesNonEmptyToken() {
        String token = jwtService.generateToken("alice", "USER");

        assertNotNull(token);
        assertFalse(token.isBlank());
        // A JWT is three base64url segments separated by dots: header.payload.signature
        assertEquals(3, token.split("\\.").length);
    }

    @Test
    void extractUsername_returnsUsernameEmbeddedAtGeneration() {
        String token = jwtService.generateToken("alice", "USER");

        assertEquals("alice", jwtService.extractUsername(token));
    }

    @Test
    void extractRole_returnsRoleEmbeddedAtGeneration() {
        String token = jwtService.generateToken("alice", "ADMIN");

        assertEquals("ADMIN", jwtService.extractRole(token));
    }

    @Test
    void isTokenValid_returnsTrue_forMatchingUsernameAndUnexpiredToken() {
        String token = jwtService.generateToken("alice", "USER");

        assertTrue(jwtService.isTokenValid("alice", token));
    }

    @Test
    void isTokenValid_returnsFalse_whenUsernameDoesNotMatch() {
        String token = jwtService.generateToken("alice", "USER");

        assertFalse(jwtService.isTokenValid("someone-else", token));
    }

    @Test
    void isTokenValid_returnsFalse_forExpiredToken() {
        // Force an already-expired token by setting a negative expiration window
        // before generating it, rather than sleeping the test thread.
        ReflectionTestUtils.setField(jwtService, "expirationMs", -ONE_HOUR_MS);
        String expiredToken = jwtService.generateToken("alice", "USER");

        assertFalse(jwtService.isTokenValid("alice", expiredToken));
    }

    @Test
    void differentUsers_produceDifferentTokens() {
        String tokenA = jwtService.generateToken("alice", "USER");
        String tokenB = jwtService.generateToken("bob", "USER");

        assertNotEquals(tokenA, tokenB);
    }
}