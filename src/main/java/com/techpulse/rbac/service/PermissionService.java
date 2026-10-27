package com.techpulse.rbac.service;

import com.techpulse.rbac.dto.request.CreatePermissionRequest;
import com.techpulse.rbac.dto.response.PermissionResponse;

import java.util.List;

public interface PermissionService {

    PermissionResponse createPermission(CreatePermissionRequest request);

    PermissionResponse getPermissionById(Long permissionId);

    List<PermissionResponse> getAllPermissions();
}
