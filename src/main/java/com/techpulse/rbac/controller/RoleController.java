package com.techpulse.rbac.controller;

import com.techpulse.rbac.dto.request.CreateRoleRequest;
import com.techpulse.rbac.dto.response.ApiResponse;
import com.techpulse.rbac.dto.response.RoleResponse;
import com.techpulse.rbac.service.RoleService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controller for Role management.
 * Protected purely by dynamic permissions via CustomPermissionEvaluator.
 * Hardcoded role checks (e.g. hasRole('ADMIN')) are strictly avoided.
 */
@RestController
@RequestMapping("/roles")
public class RoleController {

    private final RoleService roleService;

    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    /**
     * Creates a new role.
     * Evaluated dynamically: user must have 'ROLE_CREATE' permission in database.
     */
    @PostMapping
    @PreAuthorize("hasPermission(null, 'ROLE_CREATE')")
    public ResponseEntity<ApiResponse<RoleResponse>> createRole(@Valid @RequestBody CreateRoleRequest request) {
        RoleResponse response = roleService.createRole(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Role created successfully", response));
    }

    /**
     * Lists all roles and their mapped permissions.
     */
    @GetMapping
    @PreAuthorize("hasPermission(null, 'ROLE_READ')")
    public ResponseEntity<ApiResponse<List<RoleResponse>>> getAllRoles() {
        List<RoleResponse> response = roleService.getAllRoles();
        return ResponseEntity.ok(ApiResponse.success("Roles retrieved successfully", response));
    }

    /**
     * Retrieves a single role by ID.
     */
    @GetMapping("/{roleId}")
    @PreAuthorize("hasPermission(null, 'ROLE_READ')")
    public ResponseEntity<ApiResponse<RoleResponse>> getRoleById(@PathVariable Long roleId) {
        RoleResponse response = roleService.getRoleById(roleId);
        return ResponseEntity.ok(ApiResponse.success("Role retrieved successfully", response));
    }

    /**
     * Assigns a permission to a role.
     * Evaluated dynamically: user must have 'ROLE_PERMISSION_ASSIGN' permission in database.
     */
    @PostMapping("/{roleId}/permissions/{permissionId}")
    @PreAuthorize("hasPermission(null, 'ROLE_PERMISSION_ASSIGN')")
    public ResponseEntity<ApiResponse<RoleResponse>> assignPermissionToRole(@PathVariable Long roleId,
                                                                           @PathVariable Long permissionId) {
        RoleResponse response = roleService.assignPermissionToRole(roleId, permissionId);
        return ResponseEntity.ok(ApiResponse.success("Permission assigned to role successfully", response));
    }

    /**
     * Removes a permission from a role.
     * Evaluated dynamically: user must have 'ROLE_PERMISSION_DELETE' permission in database.
     */
    @DeleteMapping("/{roleId}/permissions/{permissionId}")
    @PreAuthorize("hasPermission(null, 'ROLE_PERMISSION_DELETE')")
    public ResponseEntity<ApiResponse<RoleResponse>> removePermissionFromRole(@PathVariable Long roleId,
                                                                              @PathVariable Long permissionId) {
        RoleResponse response = roleService.removePermissionFromRole(roleId, permissionId);
        return ResponseEntity.ok(ApiResponse.success("Permission removed from role successfully", response));
    }
}
