package com.techpulse.rbac.service;

import com.techpulse.rbac.dto.request.CreatePermissionRequest;
import com.techpulse.rbac.dto.response.PermissionResponse;
import com.techpulse.rbac.entity.Permission;
import com.techpulse.rbac.exception.ResourceAlreadyExistsException;
import com.techpulse.rbac.exception.ResourceNotFoundException;
import com.techpulse.rbac.repository.PermissionRepository;
import com.techpulse.rbac.service.impl.PermissionServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PermissionServiceTest {

    @Mock
    private PermissionRepository permissionRepository;

    @InjectMocks
    private PermissionServiceImpl permissionService;

    private Permission permission;

    @BeforeEach
    void setUp() {
        permission = Permission.builder().id(1L).name("ROLE_CREATE").description("Create roles").build();
    }

    @Test
    @DisplayName("createPermission succeeds with valid unique name")
    void createPermission_success() {
        CreatePermissionRequest request = CreatePermissionRequest.builder()
                .name("USER_EXPORT")
                .description("Export users")
                .build();

        when(permissionRepository.existsByNameIgnoreCase("USER_EXPORT")).thenReturn(false);
        when(permissionRepository.save(any(Permission.class))).thenAnswer(invocation -> {
            Permission p = invocation.getArgument(0);
            p.setId(2L);
            return p;
        });

        PermissionResponse response = permissionService.createPermission(request);

        assertThat(response).isNotNull();
        assertThat(response.getId()).isEqualTo(2L);
        assertThat(response.getName()).isEqualTo("USER_EXPORT");
        assertThat(response.getDescription()).isEqualTo("Export users");
    }

    @Test
    @DisplayName("createPermission throws ResourceAlreadyExistsException when permission name exists")
    void createPermission_duplicate_throwsException() {
        CreatePermissionRequest request = CreatePermissionRequest.builder()
                .name("ROLE_CREATE")
                .build();

        when(permissionRepository.existsByNameIgnoreCase("ROLE_CREATE")).thenReturn(true);

        assertThatThrownBy(() -> permissionService.createPermission(request))
                .isInstanceOf(ResourceAlreadyExistsException.class)
                .hasMessageContaining("Permission already exists with name: 'ROLE_CREATE'");
    }

    @Test
    @DisplayName("getPermissionById returns permission when found")
    void getPermissionById_success() {
        when(permissionRepository.findById(1L)).thenReturn(Optional.of(permission));

        PermissionResponse response = permissionService.getPermissionById(1L);

        assertThat(response.getId()).isEqualTo(1L);
        assertThat(response.getName()).isEqualTo("ROLE_CREATE");
    }

    @Test
    @DisplayName("getPermissionById throws ResourceNotFoundException when not found")
    void getPermissionById_notFound_throwsException() {
        when(permissionRepository.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> permissionService.getPermissionById(99L))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Permission not found with id: '99'");
    }

    @Test
    @DisplayName("getAllPermissions returns list of all permissions")
    void getAllPermissions_success() {
        when(permissionRepository.findAll()).thenReturn(List.of(permission));

        List<PermissionResponse> list = permissionService.getAllPermissions();

        assertThat(list).hasSize(1);
        assertThat(list.get(0).getName()).isEqualTo("ROLE_CREATE");
    }
}
