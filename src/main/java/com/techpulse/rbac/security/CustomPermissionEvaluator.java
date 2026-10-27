package com.techpulse.rbac.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;

/**
 * Custom PermissionEvaluator implementation for Spring Method Security.
 * Evaluates expressions like:
 *   @PreAuthorize("hasPermission(null, 'ROLE_CREATE')")
 *   @PreAuthorize("hasPermission('ROLE', 'CREATE')")
 *   @PreAuthorize("hasPermission(#id, 'Role', 'WRITE')")
 *
 * Dynamically queries RbacAuthorizationService which loads database-configured permissions at runtime.
 * Hardcoded role checks (e.g. hasRole('ADMIN')) are strictly forbidden and bypassed.
 */
@Component
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private static final Logger log = LoggerFactory.getLogger(CustomPermissionEvaluator.class);

    private final RbacAuthorizationService rbacAuthorizationService;

    public CustomPermissionEvaluator(RbacAuthorizationService rbacAuthorizationService) {
        this.rbacAuthorizationService = rbacAuthorizationService;
    }

    /**
     * Evaluates permission for target domain object (or null when target is conceptual/global).
     * Examples:
     *   hasPermission(null, 'ROLE_CREATE')
     *   hasPermission('ROLE', 'CREATE') -> matches 'ROLE_CREATE'
     */
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || permission == null) {
            log.debug("Access denied: Unauthenticated or null permission expression");
            return false;
        }

        String username = authentication.getName();
        String requiredPermission = permission.toString().trim();

        // 1. Direct permission match (e.g., 'ROLE_CREATE', 'SECURE_DATA_READ')
        if (rbacAuthorizationService.hasPermission(username, requiredPermission)) {
            return true;
        }

        // 2. Target domain object combination (e.g., target='ROLE', permission='CREATE' -> 'ROLE_CREATE')
        if (targetDomainObject != null && !targetDomainObject.toString().isBlank()) {
            String combined = targetDomainObject.toString().trim().toUpperCase() + "_" + requiredPermission.toUpperCase();
            if (rbacAuthorizationService.hasPermission(username, combined)) {
                return true;
            }
        }

        log.debug("Permission '{}' denied for user '{}'", requiredPermission, username);
        return false;
    }

    /**
     * Evaluates permission with targetId and targetType.
     * Examples:
     *   hasPermission(#roleId, 'Role', 'DELETE') -> matches 'ROLE_DELETE' or 'DELETE'
     */
    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || permission == null) {
            return false;
        }

        String username = authentication.getName();
        String requiredPermission = permission.toString().trim();

        // Check if user has targetType_permission (e.g., ROLE_DELETE) or direct permission
        if (targetType != null && !targetType.isBlank()) {
            String combined = targetType.trim().toUpperCase() + "_" + requiredPermission.toUpperCase();
            if (rbacAuthorizationService.hasPermission(username, combined)) {
                return true;
            }
        }

        return rbacAuthorizationService.hasPermission(username, requiredPermission);
    }
}
