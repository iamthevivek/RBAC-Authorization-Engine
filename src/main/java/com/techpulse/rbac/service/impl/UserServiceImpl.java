package com.techpulse.rbac.service.impl;

import com.techpulse.rbac.dto.response.UserResponse;
import com.techpulse.rbac.entity.Role;
import com.techpulse.rbac.entity.User;
import com.techpulse.rbac.entity.UserRole;
import com.techpulse.rbac.exception.ResourceAlreadyExistsException;
import com.techpulse.rbac.exception.ResourceNotFoundException;
import com.techpulse.rbac.repository.RoleRepository;
import com.techpulse.rbac.repository.UserRepository;
import com.techpulse.rbac.repository.UserRoleRepository;
import com.techpulse.rbac.security.RbacAuthorizationService;
import com.techpulse.rbac.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {

    private static final Logger log = LoggerFactory.getLogger(UserServiceImpl.class);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;
    private final RbacAuthorizationService rbacAuthorizationService;

    public UserServiceImpl(UserRepository userRepository,
                           RoleRepository roleRepository,
                           UserRoleRepository userRoleRepository,
                           RbacAuthorizationService rbacAuthorizationService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.userRoleRepository = userRoleRepository;
        this.rbacAuthorizationService = rbacAuthorizationService;
    }

    @Override
    @Transactional
    public UserResponse assignRoleToUser(Long userId, Long roleId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "id", roleId));

        if (userRoleRepository.existsByUserIdAndRoleId(userId, roleId)) {
            throw new ResourceAlreadyExistsException(
                    String.format("Role '%s' is already assigned to user '%s'", role.getName(), user.getUsername())
            );
        }

        UserRole userRole = new UserRole(user, role);
        userRoleRepository.save(userRole);

        // Invalidate dynamic cache for this user immediately
        rbacAuthorizationService.evictUser(user.getUsername());

        log.info("Assigned role '{}' (id={}) to user '{}' (id={})",
                role.getName(), roleId, user.getUsername(), userId);

        return buildUserResponse(user);
    }

    @Override
    @Transactional
    public UserResponse removeRoleFromUser(Long userId, Long roleId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "id", roleId));

        UserRole userRole = userRoleRepository.findByUserIdAndRoleId(userId, roleId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        String.format("Role '%s' is not assigned to user '%s'", role.getName(), user.getUsername())
                ));

        userRoleRepository.delete(userRole);

        // Invalidate dynamic cache for this user immediately
        rbacAuthorizationService.evictUser(user.getUsername());

        log.info("Removed role '{}' (id={}) from user '{}' (id={})",
                role.getName(), roleId, user.getUsername(), userId);

        return buildUserResponse(user);
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse getUserById(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));
        return buildUserResponse(user);
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse getUserByUsername(String username) {
        User user = userRepository.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new ResourceNotFoundException("User", "username", username));
        return buildUserResponse(user);
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserResponse> getAllUsers() {
        return userRepository.findAll().stream()
                .map(this::buildUserResponse)
                .collect(Collectors.toList());
    }

    private UserResponse buildUserResponse(User user) {
        List<Role> roles = userRoleRepository.findRolesByUserId(user.getId());
        Set<String> permissions = userRoleRepository.findPermissionNamesByUserId(user.getId());
        return UserResponse.fromEntity(user, roles, permissions);
    }
}
