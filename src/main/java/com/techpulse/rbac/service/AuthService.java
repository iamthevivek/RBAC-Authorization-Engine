package com.techpulse.rbac.service;

import com.techpulse.rbac.dto.request.LoginRequest;
import com.techpulse.rbac.dto.request.RegisterRequest;
import com.techpulse.rbac.dto.response.AuthResponse;

public interface AuthService {

    AuthResponse register(RegisterRequest request);

    AuthResponse login(LoginRequest request);
}
