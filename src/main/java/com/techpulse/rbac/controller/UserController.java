package com.techpulse.rbac.controller;

import com.techpulse.rbac.dto.response.ApiResponse;
import com.techpulse.rbac.dto.response.UserResponse;
import com.techpulse.rbac.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controller for User-Role management and user profile retrieval.
 * All assignment operations are dynamically evaluated at runtime.
 */
@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Assigns a role to a user.
     * Evaluated dynamically: user must have 'USER_ROLE_ASSIGN' permission in database.
     */
    @PostMapping("/{userId}/roles/{roleId}")
    @PreAuthorize("hasPermission(null, 'USER_ROLE_ASSIGN')")
    public ResponseEntity<ApiResponse<UserResponse>> assignRoleToUser(@PathVariable Long userId,
                                                                      @PathVariable Long roleId) {
        UserResponse response = userService.assignRoleToUser(userId, roleId);
        return ResponseEntity.ok(ApiResponse.success("Role assigned to user successfully", response));
    }

    /**
     * Removes a role from a user.
     * Evaluated dynamically: user must have 'USER_ROLE_DELETE' permission in database.
     */
    @DeleteMapping("/{userId}/roles/{roleId}")
    @PreAuthorize("hasPermission(null, 'USER_ROLE_DELETE')")
    public ResponseEntity<ApiResponse<UserResponse>> removeRoleFromUser(@PathVariable Long userId,
                                                                        @PathVariable Long roleId) {
        UserResponse response = userService.removeRoleFromUser(userId, roleId);
        return ResponseEntity.ok(ApiResponse.success("Role removed from user successfully", response));
    }

    /**
     * Retrieves user details with assigned roles and effective runtime permissions.
     */
    @GetMapping("/{userId}")
    @PreAuthorize("hasPermission(null, 'USER_READ')")
    public ResponseEntity<ApiResponse<UserResponse>> getUserById(@PathVariable Long userId) {
        UserResponse response = userService.getUserById(userId);
        return ResponseEntity.ok(ApiResponse.success("User retrieved successfully", response));
    }

    /**
     * Lists all users.
     */
    @GetMapping
    @PreAuthorize("hasPermission(null, 'USER_READ')")
    public ResponseEntity<ApiResponse<List<UserResponse>>> getAllUsers() {
        List<UserResponse> response = userService.getAllUsers();
        return ResponseEntity.ok(ApiResponse.success("Users retrieved successfully", response));
    }

    /**
     * Retrieves currently authenticated user's profile and active dynamic permissions.
     */
    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<UserResponse>> getCurrentUser(Authentication authentication) {
        UserResponse response = userService.getUserByUsername(authentication.getName());
        return ResponseEntity.ok(ApiResponse.success("Current user profile retrieved successfully", response));
    }
}
