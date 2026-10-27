package com.techpulse.rbac.initialization;

import com.techpulse.rbac.entity.*;
import com.techpulse.rbac.repository.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

/**
 * Initializes persistent RBAC seed data in H2 database.
 * Establishes roles, permissions, role-permission mappings, and initial users.
 * All authorization decisions are driven by these database entries, not hardcoded logic.
 */
@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

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
        log.info("Checking and initializing persistent RBAC database seed data...");

        // 1. Seed Permissions
        Map<String, Permission> permissions = initPermissions();

        // 2. Seed Roles
        Map<String, Role> roles = initRoles();

        // 3. Map Permissions to Roles
        initRolePermissions(roles, permissions);

        // 4. Seed Users and Map Roles
        initUsers(roles);

        log.info("RBAC database seed data successfully verified and initialized.");
    }

    private Map<String, Permission> initPermissions() {
        List<PermissionDef> definitions = List.of(
                new PermissionDef("ROLE_CREATE", "Ability to create new roles"),
                new PermissionDef("ROLE_READ", "Ability to view and list roles"),
                new PermissionDef("PERMISSION_CREATE", "Ability to create new permissions"),
                new PermissionDef("PERMISSION_READ", "Ability to view and list permissions"),
                new PermissionDef("ROLE_PERMISSION_ASSIGN", "Ability to assign a permission to a role"),
                new PermissionDef("ROLE_PERMISSION_DELETE", "Ability to revoke a permission from a role"),
                new PermissionDef("USER_ROLE_ASSIGN", "Ability to assign a role to a user"),
                new PermissionDef("USER_ROLE_DELETE", "Ability to revoke a role from a user"),
                new PermissionDef("USER_READ", "Ability to view users and their permissions"),
                new PermissionDef("SECURE_DATA_READ", "Ability to access confidential secured data endpoint")
        );

        Map<String, Permission> map = new HashMap<>();
        for (PermissionDef def : definitions) {
            Permission permission = permissionRepository.findByNameIgnoreCase(def.name())
                    .orElseGet(() -> permissionRepository.save(
                            Permission.builder()
                                    .name(def.name())
                                    .description(def.description())
                                    .build()
                    ));
            map.put(def.name(), permission);
        }
        return map;
    }

    private Map<String, Role> initRoles() {
        List<RoleDef> definitions = List.of(
                new RoleDef("ADMIN", "System Administrator with full management permissions"),
                new RoleDef("USER", "Standard End User with access to secured application resources"),
                new RoleDef("MANAGER", "Auditor / Manager with read-only visibility and secure data access")
        );

        Map<String, Role> map = new HashMap<>();
        for (RoleDef def : definitions) {
            Role role = roleRepository.findByNameIgnoreCase(def.name())
                    .orElseGet(() -> roleRepository.save(
                            Role.builder()
                                    .name(def.name())
                                    .description(def.description())
                                    .build()
                    ));
            map.put(def.name(), role);
        }
        return map;
    }

    private void initRolePermissions(Map<String, Role> roles, Map<String, Permission> permissions) {
        Role adminRole = roles.get("ADMIN");
        Role userRole = roles.get("USER");
        Role managerRole = roles.get("MANAGER");

        // ADMIN has all permissions
        for (Permission permission : permissions.values()) {
            linkRolePermission(adminRole, permission);
        }

        // USER has SECURE_DATA_READ permission
        Permission secureDataRead = permissions.get("SECURE_DATA_READ");
        if (secureDataRead != null) {
            linkRolePermission(userRole, secureDataRead);
        }

        // MANAGER has read permissions + SECURE_DATA_READ
        List.of("ROLE_READ", "PERMISSION_READ", "USER_READ", "SECURE_DATA_READ").forEach(pName -> {
            Permission p = permissions.get(pName);
            if (p != null) {
                linkRolePermission(managerRole, p);
            }
        });
    }

    private void linkRolePermission(Role role, Permission permission) {
        if (!rolePermissionRepository.existsByRoleIdAndPermissionId(role.getId(), permission.getId())) {
            rolePermissionRepository.save(new RolePermission(role, permission));
        }
    }

    private void initUsers(Map<String, Role> roles) {
        // 1. Admin User
        User adminUser = getOrCreateUser("admin", "admin123", "admin@techpulse.com");
        linkUserRole(adminUser, roles.get("ADMIN"));

        // 2. Standard User
        User standardUser = getOrCreateUser("user", "user123", "user@techpulse.com");
        linkUserRole(standardUser, roles.get("USER"));

        // 3. Manager User
        User managerUser = getOrCreateUser("manager", "manager123", "manager@techpulse.com");
        linkUserRole(managerUser, roles.get("MANAGER"));

        // 4. Guest User (No roles/permissions assigned - for testing negative access control)
        getOrCreateUser("guest", "guest123", "guest@techpulse.com");
    }

    private User getOrCreateUser(String username, String rawPassword, String email) {
        return userRepository.findByUsernameIgnoreCase(username)
                .orElseGet(() -> userRepository.save(
                        User.builder()
                                .username(username)
                                .password(passwordEncoder.encode(rawPassword))
                                .email(email)
                                .enabled(true)
                                .build()
                ));
    }

    private void linkUserRole(User user, Role role) {
        if (role != null && !userRoleRepository.existsByUserIdAndRoleId(user.getId(), role.getId())) {
            userRoleRepository.save(new UserRole(user, role));
        }
    }

    private record PermissionDef(String name, String description) {}
    private record RoleDef(String name, String description) {}
}
