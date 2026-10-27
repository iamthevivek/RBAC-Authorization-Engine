package com.techpulse.rbac.dto.response;

import com.techpulse.rbac.entity.Role;
import com.techpulse.rbac.entity.User;
import lombok.*;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserResponse {

    private Long id;
    private String username;
    private String email;
    private boolean enabled;
    @Builder.Default
    private Set<String> roles = new HashSet<>();
    @Builder.Default
    private Set<String> effectivePermissions = new HashSet<>();

    public static UserResponse fromEntity(User user, Collection<Role> roles, Collection<String> permissions) {
        if (user == null) return null;
        Set<String> roleNames = roles == null ? new HashSet<>() :
                roles.stream().map(Role::getName).collect(Collectors.toSet());
        Set<String> permSet = permissions == null ? new HashSet<>() : new HashSet<>(permissions);

        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .enabled(user.isEnabled())
                .roles(roleNames)
                .effectivePermissions(permSet)
                .build();
    }
}
