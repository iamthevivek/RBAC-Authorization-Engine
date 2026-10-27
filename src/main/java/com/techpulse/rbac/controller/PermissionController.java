package com.techpulse.rbac.controller;

import com.techpulse.rbac.dto.request.CreatePermissionRequest;
import com.techpulse.rbac.dto.response.ApiResponse;
import com.techpulse.rbac.dto.response.PermissionResponse;
import com.techpulse.rbac.service.PermissionService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controller for Permission management.
 * Protected purely by dynamic permissions via CustomPermissionEvaluator.
 */
@RestController
@RequestMapping("/permissions")
public class PermissionController {

    private final PermissionService permissionService;

    public PermissionController(PermissionService permissionService) {
        this.permissionService = permissionService;
    }

    /**
     * Creates a new permission.
     * Evaluated dynamically: user must have 'PERMISSION_CREATE' permission in database.
     */
    @PostMapping
    @PreAuthorize("hasPermission(null, 'PERMISSION_CREATE')")
    public ResponseEntity<ApiResponse<PermissionResponse>> createPermission(@Valid @RequestBody CreatePermissionRequest request) {
        PermissionResponse response = permissionService.createPermission(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Permission created successfully", response));
    }

    /**
     * Lists all permissions.
     */
    @GetMapping
    @PreAuthorize("hasPermission(null, 'PERMISSION_READ')")
    public ResponseEntity<ApiResponse<List<PermissionResponse>>> getAllPermissions() {
        List<PermissionResponse> response = permissionService.getAllPermissions();
        return ResponseEntity.ok(ApiResponse.success("Permissions retrieved successfully", response));
    }

    /**
     * Retrieves a permission by ID.
     */
    @GetMapping("/{permissionId}")
    @PreAuthorize("hasPermission(null, 'PERMISSION_READ')")
    public ResponseEntity<ApiResponse<PermissionResponse>> getPermissionById(@PathVariable Long permissionId) {
        PermissionResponse response = permissionService.getPermissionById(permissionId);
        return ResponseEntity.ok(ApiResponse.success("Permission retrieved successfully", response));
    }
}
