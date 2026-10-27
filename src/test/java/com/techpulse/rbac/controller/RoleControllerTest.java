package com.techpulse.rbac.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.techpulse.rbac.dto.request.CreateRoleRequest;
import com.techpulse.rbac.dto.response.PermissionResponse;
import com.techpulse.rbac.dto.response.RoleResponse;
import com.techpulse.rbac.service.RoleService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(RoleController.class)
@AutoConfigureMockMvc(addFilters = false)
class RoleControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private RoleService roleService;

    @Test
    @WithMockUser
    void createRole_succeeds() throws Exception {
        CreateRoleRequest request = CreateRoleRequest.builder()
                .name("AUDITOR")
                .build();

        RoleResponse response = RoleResponse.builder()
                .id(1L)
                .name("AUDITOR")
                .build();

        when(roleService.createRole(any(CreateRoleRequest.class))).thenReturn(response);

        mockMvc.perform(post("/roles")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.name").value("AUDITOR"));

        verify(roleService).createRole(any(CreateRoleRequest.class));
    }

    @Test
    @WithMockUser
    void getAllRoles_succeeds() throws Exception {
        RoleResponse r1 = RoleResponse.builder().id(1L).name("ADMIN").build();
        when(roleService.getAllRoles()).thenReturn(List.of(r1));

        mockMvc.perform(get("/roles"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[0].name").value("ADMIN"));

        verify(roleService).getAllRoles();
    }

    @Test
    @WithMockUser
    void getRoleById_succeeds() throws Exception {
        RoleResponse r1 = RoleResponse.builder().id(1L).name("ADMIN").build();
        when(roleService.getRoleById(1L)).thenReturn(r1);

        mockMvc.perform(get("/roles/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.name").value("ADMIN"));

        verify(roleService).getRoleById(1L);
    }

    @Test
    @WithMockUser
    void assignPermissionToRole_succeeds() throws Exception {
        RoleResponse r1 = RoleResponse.builder()
                .id(1L)
                .name("ADMIN")
                .permissions(Set.of(PermissionResponse.builder().id(2L).name("ROLE_CREATE").build()))
                .build();

        when(roleService.assignPermissionToRole(1L, 2L)).thenReturn(r1);

        mockMvc.perform(post("/roles/1/permissions/2").with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.name").value("ADMIN"));

        verify(roleService).assignPermissionToRole(1L, 2L);
    }

    @Test
    @WithMockUser
    void removePermissionFromRole_succeeds() throws Exception {
        RoleResponse r1 = RoleResponse.builder().id(1L).name("ADMIN").build();
        when(roleService.removePermissionFromRole(1L, 2L)).thenReturn(r1);

        mockMvc.perform(delete("/roles/1/permissions/2").with(csrf()))
                .andExpect(status().isOk());

        verify(roleService).removePermissionFromRole(1L, 2L);
    }
}
