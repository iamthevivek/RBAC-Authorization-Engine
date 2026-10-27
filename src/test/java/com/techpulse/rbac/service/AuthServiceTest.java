package com.techpulse.rbac.service;

import com.techpulse.rbac.dto.request.LoginRequest;
import com.techpulse.rbac.dto.request.RegisterRequest;
import com.techpulse.rbac.dto.response.AuthResponse;
import com.techpulse.rbac.entity.Role;
import com.techpulse.rbac.entity.User;
import com.techpulse.rbac.exception.ResourceAlreadyExistsException;
import com.techpulse.rbac.repository.RoleRepository;
import com.techpulse.rbac.repository.UserRepository;
import com.techpulse.rbac.repository.UserRoleRepository;
import com.techpulse.rbac.security.JwtTokenProvider;
import com.techpulse.rbac.service.impl.AuthServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private RoleRepository roleRepository;
    @Mock
    private UserRoleRepository userRoleRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtTokenProvider tokenProvider;

    @InjectMocks
    private AuthServiceImpl authService;

    private User user;
    private Role userRole;

    @BeforeEach
    void setUp() {
        user = User.builder().id(1L).username("alice").email("alice@techpulse.com").password("encoded").enabled(true).build();
        userRole = Role.builder().id(2L).name("USER").build();
    }

    @Test
    @DisplayName("register succeeds and assigns default USER role")
    void register_success() {
        RegisterRequest request = RegisterRequest.builder()
                .username("alice")
                .password("alice123")
                .email("alice@techpulse.com")
                .build();

        when(userRepository.existsByUsernameIgnoreCase("alice")).thenReturn(false);
        when(userRepository.existsByEmailIgnoreCase("alice@techpulse.com")).thenReturn(false);
        when(passwordEncoder.encode("alice123")).thenReturn("encoded");
        when(userRepository.save(any(User.class))).thenReturn(user);
        when(roleRepository.findByNameIgnoreCase("USER")).thenReturn(Optional.of(userRole));

        when(userRepository.findByUsernameIgnoreCase("alice")).thenReturn(Optional.of(user));
        when(userRoleRepository.findRolesByUserId(1L)).thenReturn(List.of(userRole));
        when(userRoleRepository.findPermissionNamesByUserId(1L)).thenReturn(Set.of("SECURE_DATA_READ"));
        when(tokenProvider.generateToken(anyString(), any(), any())).thenReturn("mock.jwt.token");
        when(tokenProvider.getExpirationMs()).thenReturn(86400000L);

        AuthResponse response = authService.register(request);

        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo("mock.jwt.token");
        assertThat(response.getUsername()).isEqualTo("alice");
        assertThat(response.getRoles()).contains("USER");
        assertThat(response.getPermissions()).contains("SECURE_DATA_READ");
    }

    @Test
    @DisplayName("register throws ResourceAlreadyExistsException when username is taken")
    void register_duplicateUsername_throwsException() {
        RegisterRequest request = RegisterRequest.builder()
                .username("alice")
                .password("alice123")
                .build();

        when(userRepository.existsByUsernameIgnoreCase("alice")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(ResourceAlreadyExistsException.class)
                .hasMessageContaining("User already exists with username: 'alice'");
    }

    @Test
    @DisplayName("register throws ResourceAlreadyExistsException when email is taken")
    void register_duplicateEmail_throwsException() {
        RegisterRequest request = RegisterRequest.builder()
                .username("alice")
                .password("alice123")
                .email("alice@techpulse.com")
                .build();

        when(userRepository.existsByUsernameIgnoreCase("alice")).thenReturn(false);
        when(userRepository.existsByEmailIgnoreCase("alice@techpulse.com")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(ResourceAlreadyExistsException.class)
                .hasMessageContaining("User already exists with email: 'alice@techpulse.com'");
    }

    @Test
    @DisplayName("login succeeds with valid credentials")
    void login_success() {
        LoginRequest request = LoginRequest.builder()
                .username("alice")
                .password("alice123")
                .build();

        Authentication auth = new UsernamePasswordAuthenticationToken("alice", "alice123");
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(auth);

        when(userRepository.findByUsernameIgnoreCase("alice")).thenReturn(Optional.of(user));
        when(userRoleRepository.findRolesByUserId(1L)).thenReturn(List.of(userRole));
        when(userRoleRepository.findPermissionNamesByUserId(1L)).thenReturn(Set.of("SECURE_DATA_READ"));
        when(tokenProvider.generateToken(anyString(), any(), any())).thenReturn("mock.jwt.token");
        when(tokenProvider.getExpirationMs()).thenReturn(86400000L);

        AuthResponse response = authService.login(request);

        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo("mock.jwt.token");
        assertThat(response.getUsername()).isEqualTo("alice");
    }

    @Test
    @DisplayName("login propagates BadCredentialsException")
    void login_invalidCredentials_throwsException() {
        LoginRequest request = LoginRequest.builder()
                .username("alice")
                .password("wrongpassword")
                .build();

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessageContaining("Bad credentials");
    }
}
