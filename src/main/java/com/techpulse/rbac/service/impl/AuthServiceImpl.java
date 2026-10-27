package com.techpulse.rbac.service.impl;

import com.techpulse.rbac.dto.request.LoginRequest;
import com.techpulse.rbac.dto.request.RegisterRequest;
import com.techpulse.rbac.dto.response.AuthResponse;
import com.techpulse.rbac.entity.Role;
import com.techpulse.rbac.entity.User;
import com.techpulse.rbac.entity.UserRole;
import com.techpulse.rbac.exception.ResourceAlreadyExistsException;
import com.techpulse.rbac.repository.RoleRepository;
import com.techpulse.rbac.repository.UserRepository;
import com.techpulse.rbac.repository.UserRoleRepository;
import com.techpulse.rbac.security.JwtTokenProvider;
import com.techpulse.rbac.service.AuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;

    public AuthServiceImpl(UserRepository userRepository,
                           RoleRepository roleRepository,
                           UserRoleRepository userRoleRepository,
                           PasswordEncoder passwordEncoder,
                           AuthenticationManager authenticationManager,
                           JwtTokenProvider tokenProvider) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.userRoleRepository = userRoleRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.tokenProvider = tokenProvider;
    }

    @Override
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsernameIgnoreCase(request.getUsername())) {
            throw new ResourceAlreadyExistsException("User", "username", request.getUsername());
        }
        if (request.getEmail() != null && userRepository.existsByEmailIgnoreCase(request.getEmail())) {
            throw new ResourceAlreadyExistsException("User", "email", request.getEmail());
        }

        User user = User.builder()
                .username(request.getUsername().trim())
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail() != null ? request.getEmail().trim() : null)
                .enabled(true)
                .build();

        User savedUser = userRepository.save(user);

        // Assign default USER role if it exists in DB
        Optional<Role> defaultRole = roleRepository.findByNameIgnoreCase("USER");
        defaultRole.ifPresent(role -> userRoleRepository.save(new UserRole(savedUser, role)));

        log.info("Registered new user: id={}, username={}", savedUser.getId(), savedUser.getUsername());

        return generateAuthResponse(savedUser.getUsername());
    }

    @Override
    @Transactional(readOnly = true)
    public AuthResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        String username = authentication.getName();
        return generateAuthResponse(username);
    }

    private AuthResponse generateAuthResponse(String username) {
        User user = userRepository.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new IllegalStateException("User authenticated but not found in database: " + username));

        List<Role> roles = userRoleRepository.findRolesByUserId(user.getId());
        Set<String> roleNames = roles.stream().map(Role::getName).collect(Collectors.toSet());

        Set<String> permissions = userRoleRepository.findPermissionNamesByUserId(user.getId());

        String token = tokenProvider.generateToken(
                username,
                new ArrayList<>(roleNames),
                new ArrayList<>(permissions)
        );

        return AuthResponse.builder()
                .token(token)
                .tokenType("Bearer")
                .username(username)
                .roles(roleNames)
                .permissions(permissions)
                .expiresInMs(tokenProvider.getExpirationMs())
                .build();
    }
}
