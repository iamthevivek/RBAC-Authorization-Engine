package com.techpulse.rbac.controller;

import com.techpulse.rbac.dto.response.UserResponse;
import com.techpulse.rbac.security.JwtAuthenticationFilter;
import com.techpulse.rbac.service.UserService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Set;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UserController.class)
@AutoConfigureMockMvc(addFilters = false)
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @MockBean
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Test
    @WithMockUser
    @DisplayName("POST /users/{userId}/roles/{roleId} assigns role")
    void assignRoleToUser_succeeds() throws Exception {
        UserResponse response = UserResponse.builder().id(1L).username("testuser").roles(Set.of("ADMIN")).build();
        when(userService.assignRoleToUser(1L, 2L)).thenReturn(response);

        mockMvc.perform(post("/users/1/roles/2").with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value("testuser"));

        verify(userService).assignRoleToUser(1L, 2L);
    }

    @Test
    @WithMockUser
    @DisplayName("DELETE /users/{userId}/roles/{roleId} removes role")
    void removeRoleFromUser_succeeds() throws Exception {
        UserResponse response = UserResponse.builder().id(1L).username("testuser").roles(Set.of()).build();
        when(userService.removeRoleFromUser(1L, 2L)).thenReturn(response);

        mockMvc.perform(delete("/users/1/roles/2").with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value("testuser"));

        verify(userService).removeRoleFromUser(1L, 2L);
    }

    @Test
    @WithMockUser
    @DisplayName("GET /users/{userId} returns user by ID")
    void getUserById_succeeds() throws Exception {
        UserResponse response = UserResponse.builder().id(1L).username("testuser").build();
        when(userService.getUserById(1L)).thenReturn(response);

        mockMvc.perform(get("/users/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value("testuser"));

        verify(userService).getUserById(1L);
    }

    @Test
    @WithMockUser
    @DisplayName("GET /users returns all users")
    void getAllUsers_succeeds() throws Exception {
        UserResponse response = UserResponse.builder().id(1L).username("testuser").build();
        when(userService.getAllUsers()).thenReturn(List.of(response));

        mockMvc.perform(get("/users"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[0].username").value("testuser"));

        verify(userService).getAllUsers();
    }
}
