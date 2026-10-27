package com.techpulse.rbac.controller;

import com.techpulse.rbac.dto.response.ApiResponse;
import com.techpulse.rbac.dto.response.SecureDataResponse;
import com.techpulse.rbac.service.SecureDataService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for secured business data.
 * Protected purely by dynamic database permission 'SECURE_DATA_READ'.
 * Demonstrates that USER role (or any role granted SECURE_DATA_READ) can access this resource.
 */
@RestController
@RequestMapping("/secure-data")
public class SecureDataController {

    private final SecureDataService secureDataService;

    public SecureDataController(SecureDataService secureDataService) {
        this.secureDataService = secureDataService;
    }

    /**
     * Accessible only if the user has the required 'SECURE_DATA_READ' dynamic permission.
     */
    @GetMapping
    @PreAuthorize("hasPermission(null, 'SECURE_DATA_READ')")
    public ResponseEntity<ApiResponse<SecureDataResponse>> getSecureData() {
        SecureDataResponse response = secureDataService.getSecureData();
        return ResponseEntity.ok(ApiResponse.success("Secure data retrieved successfully", response));
    }
}
