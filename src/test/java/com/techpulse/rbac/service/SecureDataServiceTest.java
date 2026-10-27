package com.techpulse.rbac.service;

import com.techpulse.rbac.dto.response.SecureDataResponse;
import com.techpulse.rbac.security.RbacAuthorizationService;
import com.techpulse.rbac.service.impl.SecureDataServiceImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SecureDataServiceTest {

    @Mock
    private RbacAuthorizationService rbacAuthorizationService;

    @InjectMocks
    private SecureDataServiceImpl secureDataService;

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void getSecureData_authenticated() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("bob", "credentials")
        );

        when(rbacAuthorizationService.getEffectivePermissions("bob"))
                .thenReturn(Set.of("SECURE_DATA_READ"));

        SecureDataResponse response = secureDataService.getSecureData();

        assertThat(response).isNotNull();
        assertThat(response.getAccessedBy()).isEqualTo("bob");
        assertThat(response.getRequiredPermission()).isEqualTo("SECURE_DATA_READ");
        assertThat(response.getData()).containsKey("confidentialReportId");
    }

    @Test
    void getSecureData_anonymous() {
        SecurityContextHolder.clearContext();

        when(rbacAuthorizationService.getEffectivePermissions("anonymous"))
                .thenReturn(Set.of());

        SecureDataResponse response = secureDataService.getSecureData();

        assertThat(response.getAccessedBy()).isEqualTo("anonymous");
    }
}
