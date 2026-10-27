package com.techpulse.rbac.service;

import com.techpulse.rbac.dto.request.CreateRoleRequest;
import com.techpulse.rbac.dto.response.RoleResponse;

import java.util.List;

public interface RoleService {

    RoleResponse createRole(CreateRoleRequest request);

    RoleResponse getRoleById(Long roleId);

    List<RoleResponse> getAllRoles();

    RoleResponse assignPermissionToRole(Long roleId, Long permissionId);

    RoleResponse removePermissionFromRole(Long roleId, Long permissionId);
}
