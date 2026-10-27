package com.techpulse.rbac.controller;

import com.techpulse.rbac.dto.response.ApiResponse;
import com.techpulse.rbac.dto.response.UserResponse;
import com.techpulse.rbac.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/{userId}/roles/{roleId}")
    @PreAuthorize("hasPermission(null, 'USER_ROLE_ASSIGN')")
    public ResponseEntity<ApiResponse<UserResponse>> assignRoleToUser(@PathVariable Long userId,
                                                                      @PathVariable Long roleId) {
        UserResponse response = userService.assignRoleToUser(userId, roleId);
        return ResponseEntity.ok(ApiResponse.success("Role assigned to user successfully", response));
    }

    @DeleteMapping("/{userId}/roles/{roleId}")
    @PreAuthorize("hasPermission(null, 'USER_ROLE_DELETE')")
    public ResponseEntity<ApiResponse<UserResponse>> removeRoleFromUser(@PathVariable Long userId,
                                                                        @PathVariable Long roleId) {
        UserResponse response = userService.removeRoleFromUser(userId, roleId);
        return ResponseEntity.ok(ApiResponse.success("Role removed from user successfully", response));
    }

    @GetMapping("/{userId}")
    @PreAuthorize("hasPermission(null, 'USER_READ')")
    public ResponseEntity<ApiResponse<UserResponse>> getUserById(@PathVariable Long userId) {
        UserResponse response = userService.getUserById(userId);
        return ResponseEntity.ok(ApiResponse.success("User retrieved successfully", response));
    }

    @GetMapping
    @PreAuthorize("hasPermission(null, 'USER_READ')")
    public ResponseEntity<ApiResponse<List<UserResponse>>> getAllUsers() {
        List<UserResponse> response = userService.getAllUsers();
        return ResponseEntity.ok(ApiResponse.success("Users retrieved successfully", response));
    }
}
