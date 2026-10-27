package com.techpulse.rbac.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomPermissionEvaluatorTest {

    @Mock
    private RbacAuthorizationService rbacAuthorizationService;

    @InjectMocks
    private CustomPermissionEvaluator permissionEvaluator;

    private Authentication authenticatedUser;

    @BeforeEach
    void setUp() {
        authenticatedUser = new UsernamePasswordAuthenticationToken(
                "john_doe", "password", AuthorityUtils.NO_AUTHORITIES
        );
    }

    @Test
    @DisplayName("hasPermission returns true when rbac service grants direct permission")
    void hasPermission_directPermission_granted() {
        when(rbacAuthorizationService.hasPermission("john_doe", "ROLE_CREATE")).thenReturn(true);

        boolean result = permissionEvaluator.hasPermission(authenticatedUser, null, "ROLE_CREATE");

        assertThat(result).isTrue();
        verify(rbacAuthorizationService).hasPermission("john_doe", "ROLE_CREATE");
    }

    @Test
    @DisplayName("hasPermission returns false when rbac service denies permission")
    void hasPermission_directPermission_denied() {
        when(rbacAuthorizationService.hasPermission("john_doe", "ROLE_CREATE")).thenReturn(false);

        boolean result = permissionEvaluator.hasPermission(authenticatedUser, null, "ROLE_CREATE");

        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("hasPermission resolves combined targetDomainObject and permission")
    void hasPermission_withTargetDomainObject_granted() {
        when(rbacAuthorizationService.hasPermission("john_doe", "CREATE")).thenReturn(false);
        when(rbacAuthorizationService.hasPermission("john_doe", "ROLE_CREATE")).thenReturn(true);

        boolean result = permissionEvaluator.hasPermission(authenticatedUser, "ROLE", "CREATE");

        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("hasPermission returns false when authentication is null or unauthenticated")
    void hasPermission_unauthenticated() {
        Authentication anonymous = new AnonymousAuthenticationToken(
                "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")
        );
        anonymous.setAuthenticated(false);

        assertThat(permissionEvaluator.hasPermission(null, null, "ROLE_CREATE")).isFalse();
        assertThat(permissionEvaluator.hasPermission(anonymous, null, "ROLE_CREATE")).isFalse();
        assertThat(permissionEvaluator.hasPermission(authenticatedUser, null, null)).isFalse();
    }

    @Test
    @DisplayName("hasPermission with targetId and targetType evaluates combined type permission")
    void hasPermission_withTargetIdAndType_granted() {
        when(rbacAuthorizationService.hasPermission("john_doe", "ROLE_DELETE")).thenReturn(true);

        boolean result = permissionEvaluator.hasPermission(authenticatedUser, 10L, "Role", "DELETE");

        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("hasPermission with targetId and targetType falls back to direct permission")
    void hasPermission_withTargetIdAndType_fallbackDirect() {
        when(rbacAuthorizationService.hasPermission("john_doe", "ROLE_DELETE")).thenReturn(false);
        when(rbacAuthorizationService.hasPermission("john_doe", "DELETE")).thenReturn(true);

        boolean result = permissionEvaluator.hasPermission(authenticatedUser, 10L, "Role", "DELETE");

        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("hasPermission with targetId returns false when unauthenticated or null")
    void hasPermission_withTargetId_invalidInputs() {
        assertThat(permissionEvaluator.hasPermission(null, 1L, "Role", "DELETE")).isFalse();
        assertThat(permissionEvaluator.hasPermission(authenticatedUser, 1L, "Role", null)).isFalse();
    }
}
