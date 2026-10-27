package com.techpulse.rbac.service;

import com.techpulse.rbac.dto.request.CreateRoleRequest;
import com.techpulse.rbac.dto.response.RoleResponse;
import com.techpulse.rbac.entity.Permission;
import com.techpulse.rbac.entity.Role;
import com.techpulse.rbac.entity.RolePermission;
import com.techpulse.rbac.exception.ResourceAlreadyExistsException;
import com.techpulse.rbac.exception.ResourceNotFoundException;
import com.techpulse.rbac.repository.PermissionRepository;
import com.techpulse.rbac.repository.RolePermissionRepository;
import com.techpulse.rbac.repository.RoleRepository;
import com.techpulse.rbac.security.RbacAuthorizationService;
import com.techpulse.rbac.service.impl.RoleServiceImpl;
import org.junit.jupiter.api.BeforeEach;
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
class RoleServiceTest {

    @Mock
    private RoleRepository roleRepository;
    @Mock
    private PermissionRepository permissionRepository;
    @Mock
    private RolePermissionRepository rolePermissionRepository;
    @Mock
    private RbacAuthorizationService rbacAuthorizationService;

    @InjectMocks
    private RoleServiceImpl roleService;

    private Role role;
    private Permission permission;

    @BeforeEach
    void setUp() {
        role = Role.builder().id(1L).name("ADMIN").build();
        permission = Permission.builder().id(10L).name("ROLE_CREATE").build();
    }

    @Test
    void createRole_success() {
        CreateRoleRequest request = CreateRoleRequest.builder()
                .name("MANAGER")
                .build();

        when(roleRepository.existsByNameIgnoreCase("MANAGER")).thenReturn(false);
        when(roleRepository.save(any(Role.class))).thenAnswer(invocation -> {
            Role r = invocation.getArgument(0);
            r.setId(2L);
            return r;
        });

        RoleResponse response = roleService.createRole(request);

        assertThat(response).isNotNull();
        assertThat(response.getId()).isEqualTo(2L);
        assertThat(response.getName()).isEqualTo("MANAGER");
    }

    @Test
    void createRole_duplicateName_throwsException() {
        CreateRoleRequest request = CreateRoleRequest.builder()
                .name("ADMIN")
                .build();

        when(roleRepository.existsByNameIgnoreCase("ADMIN")).thenReturn(true);

        assertThatThrownBy(() -> roleService.createRole(request))
                .isInstanceOf(ResourceAlreadyExistsException.class)
                .hasMessageContaining("Role already exists with name: 'ADMIN'");
    }

    @Test
    void getRoleById_success() {
        when(roleRepository.findById(1L)).thenReturn(Optional.of(role));
        when(rolePermissionRepository.findPermissionsByRoleId(1L)).thenReturn(List.of(permission));

        RoleResponse response = roleService.getRoleById(1L);

        assertThat(response.getId()).isEqualTo(1L);
        assertThat(response.getName()).isEqualTo("ADMIN");
        assertThat(response.getPermissions()).hasSize(1);
    }

    @Test
    void getRoleById_notFound_throwsException() {
        when(roleRepository.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> roleService.getRoleById(99L))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Role not found with id: '99'");
    }

    @Test
    void getAllRoles_success() {
        when(roleRepository.findAll()).thenReturn(List.of(role));
        when(rolePermissionRepository.findPermissionsByRoleId(1L)).thenReturn(List.of(permission));

        List<RoleResponse> result = roleService.getAllRoles();

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getName()).isEqualTo("ADMIN");
    }

    @Test
    void assignPermissionToRole_success() {
        when(roleRepository.findById(1L)).thenReturn(Optional.of(role));
        when(permissionRepository.findById(10L)).thenReturn(Optional.of(permission));
        when(rolePermissionRepository.existsByRoleIdAndPermissionId(1L, 10L)).thenReturn(false);
        when(rolePermissionRepository.findPermissionsByRoleId(1L)).thenReturn(List.of(permission));

        RoleResponse response = roleService.assignPermissionToRole(1L, 10L);

        assertThat(response).isNotNull();
        verify(rolePermissionRepository).save(any(RolePermission.class));
        verify(rbacAuthorizationService).evictAll();
    }

    @Test
    void assignPermissionToRole_alreadyMapped_throwsException() {
        when(roleRepository.findById(1L)).thenReturn(Optional.of(role));
        when(permissionRepository.findById(10L)).thenReturn(Optional.of(permission));
        when(rolePermissionRepository.existsByRoleIdAndPermissionId(1L, 10L)).thenReturn(true);

        assertThatThrownBy(() -> roleService.assignPermissionToRole(1L, 10L))
                .isInstanceOf(ResourceAlreadyExistsException.class)
                .hasMessageContaining("is already assigned to role");
    }

    @Test
    void assignPermissionToRole_notFound_throwsException() {
        when(roleRepository.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> roleService.assignPermissionToRole(99L, 10L))
                .isInstanceOf(ResourceNotFoundException.class);

        when(roleRepository.findById(1L)).thenReturn(Optional.of(role));
        when(permissionRepository.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> roleService.assignPermissionToRole(1L, 99L))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void removePermissionFromRole_success() {
        RolePermission rp = new RolePermission(1L, role, permission);

        when(roleRepository.findById(1L)).thenReturn(Optional.of(role));
        when(permissionRepository.findById(10L)).thenReturn(Optional.of(permission));
        when(rolePermissionRepository.findByRoleIdAndPermissionId(1L, 10L)).thenReturn(Optional.of(rp));
        when(rolePermissionRepository.findPermissionsByRoleId(1L)).thenReturn(List.of());

        RoleResponse response = roleService.removePermissionFromRole(1L, 10L);

        assertThat(response).isNotNull();
        verify(rolePermissionRepository).delete(rp);
        verify(rbacAuthorizationService).evictAll();
    }

    @Test
    void removePermissionFromRole_notMapped_throwsException() {
        when(roleRepository.findById(1L)).thenReturn(Optional.of(role));
        when(permissionRepository.findById(10L)).thenReturn(Optional.of(permission));
        when(rolePermissionRepository.findByRoleIdAndPermissionId(1L, 10L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> roleService.removePermissionFromRole(1L, 10L))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("is not mapped to role");
    }
}
