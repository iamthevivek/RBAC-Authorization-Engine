package com.techpulse.rbac.service;

import com.techpulse.rbac.dto.response.UserResponse;
import com.techpulse.rbac.entity.Role;
import com.techpulse.rbac.entity.User;
import com.techpulse.rbac.entity.UserRole;
import com.techpulse.rbac.exception.ResourceAlreadyExistsException;
import com.techpulse.rbac.exception.ResourceNotFoundException;
import com.techpulse.rbac.repository.RoleRepository;
import com.techpulse.rbac.repository.UserRepository;
import com.techpulse.rbac.repository.UserRoleRepository;
import com.techpulse.rbac.security.RbacAuthorizationService;
import com.techpulse.rbac.service.impl.UserServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private RoleRepository roleRepository;
    @Mock
    private UserRoleRepository userRoleRepository;
    @Mock
    private RbacAuthorizationService rbacAuthorizationService;

    @InjectMocks
    private UserServiceImpl userService;

    private User user;
    private Role role;

    @BeforeEach
    void setUp() {
        user = User.builder().id(1L).username("testuser").email("test@techpulse.com").enabled(true).build();
        role = Role.builder().id(5L).name("USER").description("User Role").build();
    }

    @Test
    @DisplayName("assignRoleToUser succeeds and evicts user cache")
    void assignRoleToUser_success() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(roleRepository.findById(5L)).thenReturn(Optional.of(role));
        when(userRoleRepository.existsByUserIdAndRoleId(1L, 5L)).thenReturn(false);
        when(userRoleRepository.findRolesByUserId(1L)).thenReturn(List.of(role));
        when(userRoleRepository.findPermissionNamesByUserId(1L)).thenReturn(Set.of("SECURE_DATA_READ"));

        UserResponse response = userService.assignRoleToUser(1L, 5L);

        assertThat(response).isNotNull();
        assertThat(response.getUsername()).isEqualTo("testuser");
        assertThat(response.getRoles()).contains("USER");
        assertThat(response.getEffectivePermissions()).contains("SECURE_DATA_READ");

        verify(userRoleRepository).save(any(UserRole.class));
        verify(rbacAuthorizationService).evictUser("testuser");
    }

    @Test
    @DisplayName("assignRoleToUser throws ResourceAlreadyExistsException when already assigned")
    void assignRoleToUser_duplicate_throwsException() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(roleRepository.findById(5L)).thenReturn(Optional.of(role));
        when(userRoleRepository.existsByUserIdAndRoleId(1L, 5L)).thenReturn(true);

        assertThatThrownBy(() -> userService.assignRoleToUser(1L, 5L))
                .isInstanceOf(ResourceAlreadyExistsException.class)
                .hasMessageContaining("is already assigned to user");
    }

    @Test
    @DisplayName("assignRoleToUser throws ResourceNotFoundException on non-existent user or role")
    void assignRoleToUser_notFound_throwsException() {
        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.assignRoleToUser(99L, 5L))
                .isInstanceOf(ResourceNotFoundException.class);

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(roleRepository.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.assignRoleToUser(1L, 99L))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    @DisplayName("removeRoleFromUser succeeds and evicts user cache")
    void removeRoleFromUser_success() {
        UserRole userRole = new UserRole(100L, user, role);

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(roleRepository.findById(5L)).thenReturn(Optional.of(role));
        when(userRoleRepository.findByUserIdAndRoleId(1L, 5L)).thenReturn(Optional.of(userRole));
        when(userRoleRepository.findRolesByUserId(1L)).thenReturn(List.of());
        when(userRoleRepository.findPermissionNamesByUserId(1L)).thenReturn(Set.of());

        UserResponse response = userService.removeRoleFromUser(1L, 5L);

        assertThat(response).isNotNull();
        verify(userRoleRepository).delete(userRole);
        verify(rbacAuthorizationService).evictUser("testuser");
    }

    @Test
    @DisplayName("removeRoleFromUser throws ResourceNotFoundException when mapping does not exist")
    void removeRoleFromUser_notAssigned_throwsException() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(roleRepository.findById(5L)).thenReturn(Optional.of(role));
        when(userRoleRepository.findByUserIdAndRoleId(1L, 5L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.removeRoleFromUser(1L, 5L))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("is not assigned to user");
    }

    @Test
    @DisplayName("getUserById and getUserByUsername succeed")
    void getUser_success() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRoleRepository.findRolesByUserId(1L)).thenReturn(List.of(role));
        when(userRoleRepository.findPermissionNamesByUserId(1L)).thenReturn(Set.of("SECURE_DATA_READ"));

        UserResponse responseById = userService.getUserById(1L);
        assertThat(responseById.getUsername()).isEqualTo("testuser");

        when(userRepository.findByUsernameIgnoreCase("testuser")).thenReturn(Optional.of(user));
        UserResponse responseByName = userService.getUserByUsername("testuser");
        assertThat(responseByName.getUsername()).isEqualTo("testuser");
    }

    @Test
    @DisplayName("getAllUsers returns all users with their roles and permissions")
    void getAllUsers_success() {
        when(userRepository.findAll()).thenReturn(List.of(user));
        when(userRoleRepository.findRolesByUserId(1L)).thenReturn(List.of(role));
        when(userRoleRepository.findPermissionNamesByUserId(1L)).thenReturn(Set.of("SECURE_DATA_READ"));

        List<UserResponse> list = userService.getAllUsers();
        assertThat(list).hasSize(1);
    }
}
