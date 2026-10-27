package com.techpulse.rbac.security;

import com.techpulse.rbac.repository.UserRoleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Centralized Dynamic RBAC Authorization Engine.
 * Evaluates permissions at runtime directly from database mappings.
 * Strictly avoids hardcoded role checks (e.g. hasRole('ADMIN')).
 */
@Service("rbacEngine")
public class RbacAuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(RbacAuthorizationService.class);

    private final UserRoleRepository userRoleRepository;

    @Value("${app.security.cache-enabled:true}")
    private boolean cacheEnabled;

    // In-memory cache for high-throughput runtime permission lookups
    private final Map<String, Set<String>> permissionCache = new ConcurrentHashMap<>();

    public RbacAuthorizationService(UserRoleRepository userRoleRepository) {
        this.userRoleRepository = userRoleRepository;
    }

    /**
     * Centralized dynamic permission check for a user.
     *
     * @param username       the username of the authenticated principal
     * @param permissionName the required permission (e.g., 'ROLE_CREATE', 'SECURE_DATA_READ')
     * @return true if the user's active database roles grant this permission, false otherwise
     */
    @Transactional(readOnly = true)
    public boolean hasPermission(String username, String permissionName) {
        if (username == null || permissionName == null || username.isBlank() || permissionName.isBlank()) {
            return false;
        }

        Set<String> effectivePermissions = getEffectivePermissions(username);
        boolean granted = effectivePermissions.stream()
                .anyMatch(p -> p.equalsIgnoreCase(permissionName));

        log.debug("Evaluating permission '{}' for user '{}': {}", permissionName, username, granted ? "GRANTED" : "DENIED");
        return granted;
    }

    /**
     * Centralized dynamic permission check for a user by user ID.
     */
    @Transactional(readOnly = true)
    public boolean hasPermission(Long userId, String permissionName) {
        if (userId == null || permissionName == null || permissionName.isBlank()) {
            return false;
        }
        Set<String> effectivePermissions = getEffectivePermissions(userId);
        return effectivePermissions.stream()
                .anyMatch(p -> p.equalsIgnoreCase(permissionName));
    }

    /**
     * Retrieves all dynamic permissions granted to the given user by username.
     * Uses in-memory cache if enabled, querying database on cache miss.
     */
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

    /**
     * Retrieves all dynamic permissions granted to the given user by user ID.
     */
    @Transactional(readOnly = true)
    public Set<String> getEffectivePermissions(Long userId) {
        if (userId == null) {
            return Collections.emptySet();
        }
        Set<String> permissions = userRoleRepository.findPermissionNamesByUserId(userId);
        return (permissions == null) ? Collections.emptySet() : Collections.unmodifiableSet(permissions);
    }

    /**
     * Evicts the cached permissions for a specific user.
     * Called whenever a user-role mapping is modified.
     */
    public void evictUser(String username) {
        if (username != null) {
            permissionCache.remove(username.toLowerCase());
            log.debug("Evicted permission cache for user '{}'", username);
        }
    }

    /**
     * Clears the entire permission cache.
     * Called whenever role-permission or global RBAC mappings are modified.
     */
    public void evictAll() {
        permissionCache.clear();
        log.debug("Cleared entire RBAC permission cache");
    }

    public boolean isCacheEnabled() {
        return cacheEnabled;
    }

    public void setCacheEnabled(boolean cacheEnabled) {
        this.cacheEnabled = cacheEnabled;
    }
}
