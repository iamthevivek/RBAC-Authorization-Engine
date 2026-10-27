package com.techpulse.rbac.service;

import com.techpulse.rbac.dto.response.UserResponse;

import java.util.List;

public interface UserService {

    UserResponse assignRoleToUser(Long userId, Long roleId);

    UserResponse removeRoleFromUser(Long userId, Long roleId);

    UserResponse getUserById(Long userId);

    UserResponse getUserByUsername(String username);

    List<UserResponse> getAllUsers();
}
