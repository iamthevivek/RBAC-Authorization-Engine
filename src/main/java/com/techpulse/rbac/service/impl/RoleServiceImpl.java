package com.techpulse.rbac.service.impl;

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
import com.techpulse.rbac.service.RoleService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final RbacAuthorizationService rbacAuthorizationService;

    public RoleServiceImpl(RoleRepository roleRepository,
                           PermissionRepository permissionRepository,
                           RolePermissionRepository rolePermissionRepository,
                           RbacAuthorizationService rbacAuthorizationService) {
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.rolePermissionRepository = rolePermissionRepository;
        this.rbacAuthorizationService = rbacAuthorizationService;
    }

    @Override
    @Transactional
    public RoleResponse createRole(CreateRoleRequest request) {
        String roleName = request.getName().trim().toUpperCase();
        if (roleRepository.existsByNameIgnoreCase(roleName)) {
            throw new ResourceAlreadyExistsException("Role", "name", roleName);
        }

        Role role = Role.builder()
                .name(roleName)
                .build();

        Role savedRole = roleRepository.save(role);
        return RoleResponse.fromEntity(savedRole, List.of());
    }

    @Override
    @Transactional(readOnly = true)
    public RoleResponse getRoleById(Long roleId) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "id", roleId));
        List<Permission> permissions = rolePermissionRepository.findPermissionsByRoleId(roleId);
        return RoleResponse.fromEntity(role, permissions);
    }

    @Override
    @Transactional(readOnly = true)
    public List<RoleResponse> getAllRoles() {
        return roleRepository.findAll().stream()
                .map(role -> {
                    List<Permission> permissions = rolePermissionRepository.findPermissionsByRoleId(role.getId());
                    return RoleResponse.fromEntity(role, permissions);
                })
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public RoleResponse assignPermissionToRole(Long roleId, Long permissionId) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "id", roleId));

        Permission permission = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new ResourceNotFoundException("Permission", "id", permissionId));

        if (rolePermissionRepository.existsByRoleIdAndPermissionId(roleId, permissionId)) {
            throw new ResourceAlreadyExistsException(
                    String.format("Permission '%s' is already assigned to role '%s'", permission.getName(), role.getName())
            );
        }

        RolePermission rolePermission = new RolePermission(role, permission);
        rolePermissionRepository.save(rolePermission);

        rbacAuthorizationService.evictAll();

        List<Permission> permissions = rolePermissionRepository.findPermissionsByRoleId(roleId);
        return RoleResponse.fromEntity(role, permissions);
    }

    @Override
    @Transactional
    public RoleResponse removePermissionFromRole(Long roleId, Long permissionId) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "id", roleId));

        Permission permission = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new ResourceNotFoundException("Permission", "id", permissionId));

        RolePermission rolePermission = rolePermissionRepository.findByRoleIdAndPermissionId(roleId, permissionId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        String.format("Permission '%s' is not mapped to role '%s'", permission.getName(), role.getName())
                ));

        rolePermissionRepository.delete(rolePermission);

        rbacAuthorizationService.evictAll();

        List<Permission> permissions = rolePermissionRepository.findPermissionsByRoleId(roleId);
        return RoleResponse.fromEntity(role, permissions);
    }
}
