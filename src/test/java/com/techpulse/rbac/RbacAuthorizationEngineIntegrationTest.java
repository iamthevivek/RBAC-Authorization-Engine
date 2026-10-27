package com.techpulse.rbac;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.techpulse.rbac.dto.request.CreatePermissionRequest;
import com.techpulse.rbac.dto.request.CreateRoleRequest;
import com.techpulse.rbac.entity.Role;
import com.techpulse.rbac.entity.User;
import com.techpulse.rbac.repository.PermissionRepository;
import com.techpulse.rbac.repository.RoleRepository;
import com.techpulse.rbac.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

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

    @Autowired
    private org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;

    @Test
    void createRole_asAdmin_succeeds() throws Exception {
        CreateRoleRequest request = CreateRoleRequest.builder()
                .name("TECH_LEAD")
                .build();

        mockMvc.perform(post("/roles")
                        .with(httpBasic("admin", "admin123"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.name").value("TECH_LEAD"));
    }

    @Test
    void createRole_asUser_forbidden() throws Exception {
        CreateRoleRequest request = CreateRoleRequest.builder()
                .name("UNAUTHORIZED_ROLE")
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
    void createRole_validationError_badRequest() throws Exception {
        CreateRoleRequest invalidRequest = CreateRoleRequest.builder()
                .name("")
                .build();

        mockMvc.perform(post("/roles")
                        .with(httpBasic("admin", "admin123"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.validationErrors.name").exists());
    }

    @Test
    void createPermission_asAdmin_succeeds() throws Exception {
        CreatePermissionRequest request = CreatePermissionRequest.builder()
                .name("AUDIT_LOG_EXPORT")
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

    @Test
    void assignPermissionToRole_asAdmin_succeeds() throws Exception {
        Role userRole = roleRepository.findByNameIgnoreCase("USER").orElseThrow();

        CreatePermissionRequest permReq = CreatePermissionRequest.builder()
                .name("METRICS_VIEW")
                .build();
        mockMvc.perform(post("/permissions")
                .with(httpBasic("admin", "admin123"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(permReq)));

        Long permId = permissionRepository.findByNameIgnoreCase("METRICS_VIEW").orElseThrow().getId();

        mockMvc.perform(post("/roles/" + userRole.getId() + "/permissions/" + permId)
                        .with(httpBasic("admin", "admin123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.permissions", hasItem(hasEntry("name", "METRICS_VIEW"))));
    }

    @Test
    void assignRoleToUser_asAdmin_succeeds() throws Exception {
        User guest = userRepository.findByUsernameIgnoreCase("guest").orElseThrow();
        Role userRole = roleRepository.findByNameIgnoreCase("USER").orElseThrow();

        mockMvc.perform(post("/users/" + guest.getId() + "/roles/" + userRole.getId())
                        .with(httpBasic("admin", "admin123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.roles", hasItem("USER")));
    }

    @Test
    void getSecureData_asUser_succeeds() throws Exception {
        mockMvc.perform(get("/secure-data")
                        .with(httpBasic("user", "user123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.accessedBy").value("user"))
                .andExpect(jsonPath("$.data.requiredPermission").value("SECURE_DATA_READ"))
                .andExpect(jsonPath("$.data.data.confidentialReportId").exists());
    }

    @Test
    void getSecureData_unauthenticated_unauthorized() throws Exception {
        mockMvc.perform(get("/secure-data"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void dynamicRbac_runtimeEvaluation_succeeds() throws Exception {
        User charlie = userRepository.save(User.builder().username("charlie").password(passwordEncoder.encode("charlie123")).enabled(true).build());

        mockMvc.perform(get("/secure-data")
                        .with(httpBasic("charlie", "charlie123")))
                .andExpect(status().isForbidden());

        Role userRole = roleRepository.findByNameIgnoreCase("USER").orElseThrow();
        mockMvc.perform(post("/users/" + charlie.getId() + "/roles/" + userRole.getId())
                        .with(httpBasic("admin", "admin123")))
                .andExpect(status().isOk());

        mockMvc.perform(get("/secure-data")
                        .with(httpBasic("charlie", "charlie123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }
}
