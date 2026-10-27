package com.techpulse.rbac.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.techpulse.rbac.dto.request.LoginRequest;
import com.techpulse.rbac.dto.request.RegisterRequest;
import com.techpulse.rbac.dto.response.AuthResponse;
import com.techpulse.rbac.security.JwtAuthenticationFilter;
import com.techpulse.rbac.service.AuthService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AuthService authService;

    @MockBean
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Test
    @DisplayName("POST /auth/register registers user")
    void register_succeeds() throws Exception {
        RegisterRequest request = RegisterRequest.builder()
                .username("newuser")
                .password("password123")
                .email("new@techpulse.com")
                .build();

        AuthResponse response = AuthResponse.builder().username("newuser").token("token.123").build();
        when(authService.register(any(RegisterRequest.class))).thenReturn(response);

        mockMvc.perform(post("/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.username").value("newuser"));

        verify(authService).register(any(RegisterRequest.class));
    }

    @Test
    @DisplayName("POST /auth/login authenticates user")
    void login_succeeds() throws Exception {
        LoginRequest request = LoginRequest.builder()
                .username("newuser")
                .password("password123")
                .build();

        AuthResponse response = AuthResponse.builder().username("newuser").token("token.123").build();
        when(authService.login(any(LoginRequest.class))).thenReturn(response);

        mockMvc.perform(post("/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.token").value("token.123"));

        verify(authService).login(any(LoginRequest.class));
    }
}
