package com.techpulse.rbac.security;

import com.techpulse.rbac.repository.UserRoleRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service("rbacEngine")
public class RbacAuthorizationService {

    private final UserRoleRepository userRoleRepository;

    @Value("${app.security.cache-enabled:true}")
    private boolean cacheEnabled;

    private final Map<String, Set<String>> permissionCache = new ConcurrentHashMap<>();

    public RbacAuthorizationService(UserRoleRepository userRoleRepository) {
        this.userRoleRepository = userRoleRepository;
    }

    @Transactional(readOnly = true)
    public boolean hasPermission(String username, String permissionName) {
        if (username == null || permissionName == null || username.isBlank() || permissionName.isBlank()) {
            return false;
        }

        Set<String> effectivePermissions = getEffectivePermissions(username);
        return effectivePermissions.stream()
                .anyMatch(p -> p.equalsIgnoreCase(permissionName));
    }

    @Transactional(readOnly = true)
    public boolean hasPermission(Long userId, String permissionName) {
        if (userId == null || permissionName == null || permissionName.isBlank()) {
            return false;
        }
        Set<String> effectivePermissions = getEffectivePermissions(userId);
        return effectivePermissions.stream()
                .anyMatch(p -> p.equalsIgnoreCase(permissionName));
    }

    @Transactional(readOnly = true)
    public Set<String> getEffectivePermissions(String username) {
        if (username == null || username.isBlank()) {
            return Collections.emptySet();
        }

        String key = username.toLowerCase();
        if (cacheEnabled && permissionCache.containsKey(key)) {
            return permissionCache.get(key);
        }

        Set<String> permissions = userRoleRepository.findPermissionNamesByUsername(username);
        Set<String> safeSet = (permissions == null) ? Collections.emptySet() : Collections.unmodifiableSet(permissions);

        if (cacheEnabled) {
            permissionCache.put(key, safeSet);
        }
        return safeSet;
    }

    @Transactional(readOnly = true)
    public Set<String> getEffectivePermissions(Long userId) {
        if (userId == null) {
            return Collections.emptySet();
        }
        Set<String> permissions = userRoleRepository.findPermissionNamesByUserId(userId);
        return (permissions == null) ? Collections.emptySet() : Collections.unmodifiableSet(permissions);
    }

    public void evictUser(String username) {
        if (username != null) {
            permissionCache.remove(username.toLowerCase());
        }
    }

    public void evictAll() {
        permissionCache.clear();
    }

    public boolean isCacheEnabled() {
        return cacheEnabled;
    }

    public void setCacheEnabled(boolean cacheEnabled) {
        this.cacheEnabled = cacheEnabled;
    }
}
