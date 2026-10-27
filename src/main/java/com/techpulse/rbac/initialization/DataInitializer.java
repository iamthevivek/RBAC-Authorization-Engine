package com.techpulse.rbac.initialization;

import com.techpulse.rbac.entity.*;
import com.techpulse.rbac.repository.*;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Component
public class DataInitializer implements CommandLineRunner {

    private final PermissionRepository permissionRepository;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final UserRoleRepository userRoleRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(PermissionRepository permissionRepository,
                           RoleRepository roleRepository,
                           UserRepository userRepository,
                           RolePermissionRepository rolePermissionRepository,
                           UserRoleRepository userRoleRepository,
                           PasswordEncoder passwordEncoder) {
        this.permissionRepository = permissionRepository;
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.rolePermissionRepository = rolePermissionRepository;
        this.userRoleRepository = userRoleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public void run(String... args) {
        Map<String, Permission> permissions = initPermissions();
        Map<String, Role> roles = initRoles();
        initRolePermissions(roles, permissions);
        initUsers(roles);
    }

    private Map<String, Permission> initPermissions() {
        List<String> names = List.of(
                "ROLE_CREATE",
                "ROLE_READ",
                "PERMISSION_CREATE",
                "PERMISSION_READ",
                "ROLE_PERMISSION_ASSIGN",
                "ROLE_PERMISSION_DELETE",
                "USER_ROLE_ASSIGN",
                "USER_ROLE_DELETE",
                "USER_READ",
                "SECURE_DATA_READ"
        );

        Map<String, Permission> map = new HashMap<>();
        for (String name : names) {
            Permission permission = permissionRepository.findByNameIgnoreCase(name)
                    .orElseGet(() -> permissionRepository.save(new Permission(name)));
            map.put(name, permission);
        }
        return map;
    }

    private Map<String, Role> initRoles() {
        List<String> names = List.of("ADMIN", "USER");

        Map<String, Role> map = new HashMap<>();
        for (String name : names) {
            Role role = roleRepository.findByNameIgnoreCase(name)
                    .orElseGet(() -> roleRepository.save(new Role(name)));
            map.put(name, role);
        }
        return map;
    }

    private void initRolePermissions(Map<String, Role> roles, Map<String, Permission> permissions) {
        Role adminRole = roles.get("ADMIN");
        Role userRole = roles.get("USER");

        for (Permission permission : permissions.values()) {
            linkRolePermission(adminRole, permission);
        }

        Permission secureDataRead = permissions.get("SECURE_DATA_READ");
        if (secureDataRead != null) {
            linkRolePermission(userRole, secureDataRead);
        }
    }

    private void linkRolePermission(Role role, Permission permission) {
        if (!rolePermissionRepository.existsByRoleIdAndPermissionId(role.getId(), permission.getId())) {
            rolePermissionRepository.save(new RolePermission(role, permission));
        }
    }

    private void initUsers(Map<String, Role> roles) {
        User adminUser = getOrCreateUser("admin", "admin123");
        linkUserRole(adminUser, roles.get("ADMIN"));

        User standardUser = getOrCreateUser("user", "user123");
        linkUserRole(standardUser, roles.get("USER"));
    }

    private User getOrCreateUser(String username, String rawPassword) {
        return userRepository.findByUsernameIgnoreCase(username)
                .orElseGet(() -> userRepository.save(
                        User.builder()
                                .username(username)
                                .password(passwordEncoder.encode(rawPassword))
                                .enabled(true)
                                .build()
                ));
    }

    private void linkUserRole(User user, Role role) {
        if (role != null && !userRoleRepository.existsByUserIdAndRoleId(user.getId(), role.getId())) {
            userRoleRepository.save(new UserRole(user, role));
        }
    }
}
