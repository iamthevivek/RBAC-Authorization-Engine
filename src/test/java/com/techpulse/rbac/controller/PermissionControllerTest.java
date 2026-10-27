package com.techpulse.rbac.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.techpulse.rbac.dto.request.CreatePermissionRequest;
import com.techpulse.rbac.dto.response.PermissionResponse;
import com.techpulse.rbac.service.PermissionService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(PermissionController.class)
@AutoConfigureMockMvc(addFilters = false)
class PermissionControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private PermissionService permissionService;

    @Test
    @WithMockUser
    void createPermission_succeeds() throws Exception {
        CreatePermissionRequest request = CreatePermissionRequest.builder()
                .name("REPORT_VIEW")
                .build();

        PermissionResponse response = PermissionResponse.builder()
                .id(1L)
                .name("REPORT_VIEW")
                .build();

        when(permissionService.createPermission(any(CreatePermissionRequest.class))).thenReturn(response);

        mockMvc.perform(post("/permissions")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.name").value("REPORT_VIEW"));

        verify(permissionService).createPermission(any(CreatePermissionRequest.class));
    }

    @Test
    @WithMockUser
    void getAllPermissions_succeeds() throws Exception {
        PermissionResponse p = PermissionResponse.builder().id(1L).name("ROLE_CREATE").build();
        when(permissionService.getAllPermissions()).thenReturn(List.of(p));

        mockMvc.perform(get("/permissions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[0].name").value("ROLE_CREATE"));

        verify(permissionService).getAllPermissions();
    }

    @Test
    @WithMockUser
    void getPermissionById_succeeds() throws Exception {
        PermissionResponse p = PermissionResponse.builder().id(1L).name("ROLE_CREATE").build();
        when(permissionService.getPermissionById(1L)).thenReturn(p);

        mockMvc.perform(get("/permissions/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.name").value("ROLE_CREATE"));

        verify(permissionService).getPermissionById(1L);
    }
}
