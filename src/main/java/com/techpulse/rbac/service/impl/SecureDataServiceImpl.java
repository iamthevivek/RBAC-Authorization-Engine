package com.techpulse.rbac.service.impl;

import com.techpulse.rbac.dto.response.SecureDataResponse;
import com.techpulse.rbac.security.RbacAuthorizationService;
import com.techpulse.rbac.service.SecureDataService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Service
public class SecureDataServiceImpl implements SecureDataService {

    private final RbacAuthorizationService rbacAuthorizationService;

    public SecureDataServiceImpl(RbacAuthorizationService rbacAuthorizationService) {
        this.rbacAuthorizationService = rbacAuthorizationService;
    }

    @Override
    public SecureDataResponse getSecureData() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = (auth != null) ? auth.getName() : "anonymous";
        Set<String> effectivePermissions = rbacAuthorizationService.getEffectivePermissions(username);

        Map<String, Object> payload = new HashMap<>();
        payload.put("confidentialReportId", "REP-TECHPULSE-2026-X99");
        payload.put("dataClassification", "CONFIDENTIAL / INTERNAL RESTRICTED");
        payload.put("financialMetrics", Map.of("revenue", 12500000, "currency", "USD", "status", "AUDITED"));
        payload.put("activeDatabasePermissions", effectivePermissions);

        return SecureDataResponse.builder()
                .message("Confidential enterprise resource accessed successfully.")
                .accessedBy(username)
                .requiredPermission("SECURE_DATA_READ")
                .timestamp(LocalDateTime.now())
                .payload(payload)
                .build();
    }
}
