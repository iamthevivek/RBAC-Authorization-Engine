package com.techpulse.rbac.service.impl;

import com.techpulse.rbac.dto.request.CreatePermissionRequest;
import com.techpulse.rbac.dto.response.PermissionResponse;
import com.techpulse.rbac.entity.Permission;
import com.techpulse.rbac.exception.ResourceAlreadyExistsException;
import com.techpulse.rbac.exception.ResourceNotFoundException;
import com.techpulse.rbac.repository.PermissionRepository;
import com.techpulse.rbac.service.PermissionService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class PermissionServiceImpl implements PermissionService {

    private final PermissionRepository permissionRepository;

    public PermissionServiceImpl(PermissionRepository permissionRepository) {
        this.permissionRepository = permissionRepository;
    }

    @Override
    @Transactional
    public PermissionResponse createPermission(CreatePermissionRequest request) {
        String permissionName = request.getName().trim().toUpperCase();
        if (permissionRepository.existsByNameIgnoreCase(permissionName)) {
            throw new ResourceAlreadyExistsException("Permission", "name", permissionName);
        }

        Permission permission = Permission.builder()
                .name(permissionName)
                .build();

        Permission saved = permissionRepository.save(permission);
        return PermissionResponse.fromEntity(saved);
    }

    @Override
    @Transactional(readOnly = true)
    public PermissionResponse getPermissionById(Long permissionId) {
        Permission permission = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new ResourceNotFoundException("Permission", "id", permissionId));
        return PermissionResponse.fromEntity(permission);
    }

    @Override
    @Transactional(readOnly = true)
    public List<PermissionResponse> getAllPermissions() {
        return permissionRepository.findAll().stream()
                .map(PermissionResponse::fromEntity)
                .collect(Collectors.toList());
    }
}
