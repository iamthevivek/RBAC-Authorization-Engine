package com.techpulse.rbac.security;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;

@Component
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private final RbacAuthorizationService rbacAuthorizationService;

    public CustomPermissionEvaluator(RbacAuthorizationService rbacAuthorizationService) {
        this.rbacAuthorizationService = rbacAuthorizationService;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || permission == null) {
            return false;
        }

        String username = authentication.getName();
        String requiredPermission = permission.toString().trim();

        if (rbacAuthorizationService.hasPermission(username, requiredPermission)) {
            return true;
        }

        if (targetDomainObject != null && !targetDomainObject.toString().isBlank()) {
            String combined = targetDomainObject.toString().trim().toUpperCase() + "_" + requiredPermission.toUpperCase();
            if (rbacAuthorizationService.hasPermission(username, combined)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || permission == null) {
            return false;
        }

        String username = authentication.getName();
        String requiredPermission = permission.toString().trim();

        if (targetType != null && !targetType.isBlank()) {
            String combined = targetType.trim().toUpperCase() + "_" + requiredPermission.toUpperCase();
            if (rbacAuthorizationService.hasPermission(username, combined)) {
                return true;
            }
        }

        return rbacAuthorizationService.hasPermission(username, requiredPermission);
    }
}
