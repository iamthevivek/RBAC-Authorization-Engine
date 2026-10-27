package com.techpulse.rbac;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.techpulse.rbac.dto.request.CreatePermissionRequest;
import com.techpulse.rbac.dto.request.CreateRoleRequest;
import com.techpulse.rbac.dto.request.LoginRequest;
import com.techpulse.rbac.dto.request.RegisterRequest;
import com.techpulse.rbac.entity.Role;
import com.techpulse.rbac.entity.User;
import com.techpulse.rbac.repository.PermissionRepository;
import com.techpulse.rbac.repository.RoleRepository;
import com.techpulse.rbac.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class RbacAuthorizationEngineIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PermissionRepository permissionRepository;

    @Autowired
    private UserRepository userRepository;

    // -------------------------------------------------------------
    // API: POST /roles (Role: ADMIN with 'ROLE_CREATE' permission)
    // -------------------------------------------------------------

    @Test
    @DisplayName("POST /roles - Admin with 'ROLE_CREATE' creates a new role successfully")
    void createRole_asAdmin_succeeds() throws Exception {
        CreateRoleRequest request = CreateRoleRequest.builder()
                .name("TECH_LEAD")
                .description("Technical Lead Role")
                .build();

        mockMvc.perform(post("/roles")
                        .with(httpBasic("admin", "admin123"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.name").value("TECH_LEAD"))
                .andExpect(jsonPath("$.data.description").value("Technical Lead Role"));
    }

    @Test
    @DisplayName("POST /roles - User without 'ROLE_CREATE' receives 403 Forbidden")
    void createRole_asUser_forbidden() throws Exception {
        CreateRoleRequest request = CreateRoleRequest.builder()
                .name("UNAUTHORIZED_ROLE")
                .description("Should be rejected")
                .build();

        mockMvc.perform(post("/roles")
                        .with(httpBasic("user", "user123"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.message").value(containsString("Access denied")));
    }

    @Test
    @DisplayName("POST /roles - Unauthenticated request receives 401 Unauthorized")
    void createRole_unauthenticated_unauthorized() throws Exception {
        CreateRoleRequest request = CreateRoleRequest.builder()
                .name("ANONYMOUS_ROLE")
                .build();

        mockMvc.perform(post("/roles")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /roles - Payload validation failure returns 400 Bad Request with field errors")
    void createRole_validationError_badRequest() throws Exception {
        CreateRoleRequest invalidRequest = CreateRoleRequest.builder()
                .name("") // Blank name violates @NotBlank
                .build();

        mockMvc.perform(post("/roles")
                        .with(httpBasic("admin", "admin123"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.validationErrors.name").exists());
    }

    // -------------------------------------------------------------
    // API: POST /permissions (Role: ADMIN with 'PERMISSION_CREATE')
    // -------------------------------------------------------------

    @Test
    @DisplayName("POST /permissions - Admin with 'PERMISSION_CREATE' creates permission successfully")
    void createPermission_asAdmin_succeeds() throws Exception {
        CreatePermissionRequest request = CreatePermissionRequest.builder()
                .name("AUDIT_LOG_EXPORT")
                .description("Permission to export system audit logs")
                .build();

        mockMvc.perform(post("/permissions")
                        .with(httpBasic("admin", "admin123"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.name").value("AUDIT_LOG_EXPORT"));
    }

    @Test
    @DisplayName("POST /permissions - Standard user receives 403 Forbidden")
    void createPermission_asUser_forbidden() throws Exception {
        CreatePermissionRequest request = CreatePermissionRequest.builder()
                .name("FORBIDDEN_PERM")
                .build();

        mockMvc.perform(post("/permissions")
                        .with(httpBasic("user", "user123"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    // ---------------------------------------------------------------------------------
    // API: POST /roles/{roleId}/permissions/{permissionId} (Role: ADMIN)
    // ---------------------------------------------------------------------------------

    @Test
    @DisplayName("POST /roles/{roleId}/permissions/{permissionId} - Assigns permission to role dynamically")
    void assignPermissionToRole_asAdmin_succeeds() throws Exception {
        Role managerRole = roleRepository.findByNameIgnoreCase("MANAGER").orElseThrow();

        // Create a new unique permission for testing
        CreatePermissionRequest permReq = CreatePermissionRequest.builder()
                .name("METRICS_VIEW")
                .description("View metrics")
                .build();
        mockMvc.perform(post("/permissions")
                .with(httpBasic("admin", "admin123"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(permReq)));

        Long permId = permissionRepository.findByNameIgnoreCase("METRICS_VIEW").orElseThrow().getId();

        mockMvc.perform(post("/roles/" + managerRole.getId() + "/permissions/" + permId)
                        .with(httpBasic("admin", "admin123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.permissions", hasItem(hasEntry("name", "METRICS_VIEW"))));
    }

    // ---------------------------------------------------------------------------------
    // API: POST /users/{userId}/roles/{roleId} (Role: ADMIN)
    // ---------------------------------------------------------------------------------

    @Test
    @DisplayName("POST /users/{userId}/roles/{roleId} - Assigns role to user dynamically")
    void assignRoleToUser_asAdmin_succeeds() throws Exception {
        User guest = userRepository.findByUsernameIgnoreCase("guest").orElseThrow();
        Role managerRole = roleRepository.findByNameIgnoreCase("MANAGER").orElseThrow();

        mockMvc.perform(post("/users/" + guest.getId() + "/roles/" + managerRole.getId())
                        .with(httpBasic("admin", "admin123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.roles", hasItem("MANAGER")));
    }

    // -------------------------------------------------------------
    // API: GET /secure-data (Requires 'SECURE_DATA_READ' permission)
    // -------------------------------------------------------------

    @Test
    @DisplayName("GET /secure-data - User with 'SECURE_DATA_READ' permission accesses secured data")
    void getSecureData_asUser_succeeds() throws Exception {
        mockMvc.perform(get("/secure-data")
                        .with(httpBasic("user", "user123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.accessedBy").value("user"))
                .andExpect(jsonPath("$.data.requiredPermission").value("SECURE_DATA_READ"))
                .andExpect(jsonPath("$.data.payload.confidentialReportId").exists());
    }

    @Test
    @DisplayName("GET /secure-data - Unauthenticated request receives 401 Unauthorized")
    void getSecureData_unauthenticated_unauthorized() throws Exception {
        mockMvc.perform(get("/secure-data"))
                .andExpect(status().isUnauthorized());
    }

    // --------------------------------------------------------------------------
    // Dynamic RBAC Demonstration: Runtime Permission Evaluation Without Restart
    // --------------------------------------------------------------------------

    @Test
    @DisplayName("Dynamic RBAC: New user initially denied, granted permission dynamically, succeeds immediately")
    void dynamicRbac_runtimeEvaluation_succeeds() throws Exception {
        // 1. Register a brand new user 'charlie' with no roles
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("charlie")
                .password("charlie123")
                .email("charlie@techpulse.com")
                .build();

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());

        User charlie = userRepository.findByUsernameIgnoreCase("charlie").orElseThrow();

        // 2. Charlie attempts to access /roles (requires ROLE_READ) -> 403 Forbidden
        mockMvc.perform(get("/roles")
                        .with(httpBasic("charlie", "charlie123")))
                .andExpect(status().isForbidden());

        // 3. Admin dynamically assigns 'ADMIN' role to Charlie
        Role adminRole = roleRepository.findByNameIgnoreCase("ADMIN").orElseThrow();
        mockMvc.perform(post("/users/" + charlie.getId() + "/roles/" + adminRole.getId())
                        .with(httpBasic("admin", "admin123")))
                .andExpect(status().isOk());

        // 4. Charlie immediately re-attempts to access /roles -> 200 OK!
        mockMvc.perform(get("/roles")
                        .with(httpBasic("charlie", "charlie123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    // -------------------------------------------------------------
    // JWT Authentication & Token Lifecycle Test
    // -------------------------------------------------------------

    @Test
    @DisplayName("JWT: Login returns Bearer token, which successfully authenticates requests")
    void jwtAuthentication_flow_succeeds() throws Exception {
        LoginRequest loginRequest = LoginRequest.builder()
                .username("user")
                .password("user123")
                .build();

        MvcResult result = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.token").isString())
                .andExpect(jsonPath("$.data.tokenType").value("Bearer"))
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        String token = objectMapper.readTree(responseBody).path("data").path("token").asText();

        // Call /secure-data with the Bearer token
        mockMvc.perform(get("/secure-data")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessedBy").value("user"));
    }

    @Test
    @DisplayName("GET /users/me - Retrieves current user profile and permissions")
    void getCurrentUser_succeeds() throws Exception {
        mockMvc.perform(get("/users/me")
                        .with(httpBasic("admin", "admin123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value("admin"))
                .andExpect(jsonPath("$.data.effectivePermissions", hasItem("ROLE_CREATE")));
    }
}
