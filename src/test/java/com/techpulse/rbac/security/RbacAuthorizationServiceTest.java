package com.techpulse.rbac.security;

import com.techpulse.rbac.repository.UserRoleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RbacAuthorizationServiceTest {

    @Mock
    private UserRoleRepository userRoleRepository;

    @InjectMocks
    private RbacAuthorizationService rbacAuthorizationService;

    @BeforeEach
    void setUp() {
        rbacAuthorizationService.setCacheEnabled(true);
        rbacAuthorizationService.evictAll();
    }

    @Test
    void hasPermission_username_granted() {
        when(userRoleRepository.findPermissionNamesByUsername("admin"))
                .thenReturn(Set.of("ROLE_CREATE", "USER_ROLE_ASSIGN"));

        boolean result = rbacAuthorizationService.hasPermission("admin", "ROLE_CREATE");

        assertThat(result).isTrue();
        verify(userRoleRepository, times(1)).findPermissionNamesByUsername("admin");

        boolean secondResult = rbacAuthorizationService.hasPermission("admin", "ROLE_CREATE");
        assertThat(secondResult).isTrue();
        verifyNoMoreInteractions(userRoleRepository);
    }

    @Test
    void hasPermission_username_caseInsensitive() {
        when(userRoleRepository.findPermissionNamesByUsername("admin"))
                .thenReturn(Set.of("ROLE_CREATE"));

        boolean result = rbacAuthorizationService.hasPermission("admin", "role_create");

        assertThat(result).isTrue();
    }

    @Test
    void hasPermission_invalidInputs() {
        when(userRoleRepository.findPermissionNamesByUsername("user"))
                .thenReturn(Set.of("SECURE_DATA_READ"));

        assertThat(rbacAuthorizationService.hasPermission("user", "ROLE_CREATE")).isFalse();
        assertThat(rbacAuthorizationService.hasPermission("", "ROLE_CREATE")).isFalse();
        assertThat(rbacAuthorizationService.hasPermission((String) null, "ROLE_CREATE")).isFalse();
        assertThat(rbacAuthorizationService.hasPermission((Long) null, "ROLE_CREATE")).isFalse();
        assertThat(rbacAuthorizationService.hasPermission("user", null)).isFalse();
        assertThat(rbacAuthorizationService.hasPermission("user", "  ")).isFalse();
    }

    @Test
    void hasPermission_userId_granted() {
        when(userRoleRepository.findPermissionNamesByUserId(1L))
                .thenReturn(Set.of("SECURE_DATA_READ"));

        assertThat(rbacAuthorizationService.hasPermission(1L, "SECURE_DATA_READ")).isTrue();
        assertThat(rbacAuthorizationService.hasPermission(1L, "ROLE_CREATE")).isFalse();
        assertThat(rbacAuthorizationService.hasPermission((Long) null, "SECURE_DATA_READ")).isFalse();
        assertThat(rbacAuthorizationService.hasPermission(1L, null)).isFalse();
    }

    @Test
    void evictUser_clearsUserEntry() {
        when(userRoleRepository.findPermissionNamesByUsername("user1"))
                .thenReturn(Set.of("SECURE_DATA_READ"));

        rbacAuthorizationService.hasPermission("user1", "SECURE_DATA_READ");
        verify(userRoleRepository, times(1)).findPermissionNamesByUsername("user1");

        rbacAuthorizationService.evictUser("user1");

        rbacAuthorizationService.hasPermission("user1", "SECURE_DATA_READ");
        verify(userRoleRepository, times(2)).findPermissionNamesByUsername("user1");
    }

    @Test
    void evictAll_clearsAllEntries() {
        when(userRoleRepository.findPermissionNamesByUsername("user1"))
                .thenReturn(Set.of("SECURE_DATA_READ"));
        when(userRoleRepository.findPermissionNamesByUsername("user2"))
                .thenReturn(Set.of("ROLE_CREATE"));

        rbacAuthorizationService.hasPermission("user1", "SECURE_DATA_READ");
        rbacAuthorizationService.hasPermission("user2", "ROLE_CREATE");

        rbacAuthorizationService.evictAll();

        rbacAuthorizationService.hasPermission("user1", "SECURE_DATA_READ");
        rbacAuthorizationService.hasPermission("user2", "ROLE_CREATE");

        verify(userRoleRepository, times(2)).findPermissionNamesByUsername("user1");
        verify(userRoleRepository, times(2)).findPermissionNamesByUsername("user2");
    }

    @Test
    void getEffectivePermissions_emptyInputs() {
        assertThat(rbacAuthorizationService.getEffectivePermissions((String) null)).isEmpty();
        assertThat(rbacAuthorizationService.getEffectivePermissions("")).isEmpty();
        assertThat(rbacAuthorizationService.getEffectivePermissions((Long) null)).isEmpty();
    }

    @Test
    void cacheDisabled_queriesEveryTime() {
        rbacAuthorizationService.setCacheEnabled(false);
        assertThat(rbacAuthorizationService.isCacheEnabled()).isFalse();

        when(userRoleRepository.findPermissionNamesByUsername("user1"))
                .thenReturn(Set.of("SECURE_DATA_READ"));

        rbacAuthorizationService.hasPermission("user1", "SECURE_DATA_READ");
        rbacAuthorizationService.hasPermission("user1", "SECURE_DATA_READ");

        verify(userRoleRepository, times(2)).findPermissionNamesByUsername("user1");
    }
}
