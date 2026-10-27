package com.techpulse.rbac.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JwtTokenProviderTest {

    private JwtTokenProvider tokenProvider;
    private final String secret = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    private final long expirationMs = 3600000;

    @BeforeEach
    void setUp() {
        tokenProvider = new JwtTokenProvider(secret, expirationMs);
    }

    @Test
    @DisplayName("generateToken produces a valid token that can extract username and claims")
    void generateToken_and_validate() {
        String token = tokenProvider.generateToken("alice", List.of("USER"), List.of("SECURE_DATA_READ"));

        assertThat(token).isNotBlank();
        assertThat(tokenProvider.validateToken(token)).isTrue();
        assertThat(tokenProvider.getUsernameFromToken(token)).isEqualTo("alice");
        assertThat(tokenProvider.getExpirationMs()).isEqualTo(expirationMs);
    }

    @Test
    @DisplayName("validateToken returns false on tampered or malformed token")
    void validateToken_invalidToken() {
        assertThat(tokenProvider.validateToken("invalid.jwt.token")).isFalse();
        assertThat(tokenProvider.validateToken("")).isFalse();
        assertThat(tokenProvider.validateToken(null)).isFalse();
    }
}
